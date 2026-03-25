package dnscrypt

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
)

// normalize truncates the DNS response if needed depending on the protocol.
// req and res must not be nil.
func normalize(proto Proto, req, res *dns.Msg) {
	size := dnsSize(proto, req)
	// DNSCrypt encryption adds a header to each message, we should consider
	// this when truncating a message.  64 should cover all cases.
	size = size - 64

	// Truncate response message
	res.Truncate(size)

	// In case of UDP it is safer to simply remove all response records
	// [dns.Msg.Truncate] method will not consider that we need a response
	// shorter than [dns.MinMsgSize].
	if res.Truncated && proto == ProtoUDP {
		res.Answer = nil
	}
}

// dnsSize returns buffer size advertised in the requests OPT record.  When the
// request was over TCP, it returns the maximum allowed size of 64K.  r must not
// be nil.
func dnsSize(proto Proto, r *dns.Msg) (res int) {
	size := uint16(0)
	if o := r.IsEdns0(); o != nil {
		size = o.UDPSize()
	}

	if proto != ProtoUDP {
		return dns.MaxMsgSize
	}

	if size < dns.MinMsgSize {
		return dns.MinMsgSize
	}

	// normalize size.
	return int(size)
}

// readPrefixed reads a DNS message with a 2-byte prefix containing message
// length.  conn must not be nil.
func readPrefixed(conn net.Conn) (b []byte, err error) {
	l := make([]byte, 2)
	_, err = conn.Read(l)
	if err != nil {
		return nil, fmt.Errorf("reading msg len: %w", err)
	}

	packetLen := binary.BigEndian.Uint16(l)
	if packetLen > dns.MaxMsgSize {
		return nil, ErrQueryTooLarge
	}

	buf := make([]byte, packetLen)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, fmt.Errorf("reading full message: %w", err)
	}

	return buf, nil
}

// writePrefixed writes a prefixed DNS message to a TCP connection.  conn must
// not be nil.
func writePrefixed(b []byte, conn net.Conn) (err error) {
	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(b)))
	_, err = (&net.Buffers{l, b}).WriteTo(conn)

	return errors.Annotate(err, "writing to connection: %w")
}
