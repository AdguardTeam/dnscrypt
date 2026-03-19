package dnscrypt

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/AdguardTeam/dnscrypt/internal/xsecretbox"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
	"golang.org/x/crypto/nacl/box"
)

// Prior to encryption, queries are padded using the ISO/IEC 7816-4 format.  The
// padding starts with a byte valued 0x80 followed by a variable number of NUL
// bytes.
//
// # Padding for client queries over UDP
//
// <client-query> <client-query-pad> must be at least <min-query-len> bytes.  If
// the length of the client query is less than <min-query-len>, the padding
// length must be adjusted in order to satisfy this requirement.
//
// <min-query-len> is a variable length, initially set to 256 bytes, and must be
// a multiple of 64 bytes.
//
// # Padding for client queries over TCP
//
// The length of <client-query-pad> is randomly chosen between 1 and 256 bytes
// (including the leading 0x80), but the total length of <client-query>
// <client-query-pad> must be a multiple of 64 bytes.
//
// For example, an originally unpadded 56-bytes DNS query can be padded as:
//	<56-bytes-query> 0x80 0x00 0x00 0x00 0x00 0x00 0x00 0x00
//	or
//	<56-bytes-query> 0x80 (0x00 * 71)
//	or
//	<56-bytes-query> 0x80 (0x00 * 135)
//	or
//	<56-bytes-query> 0x80 (0x00 * 199)

// pad performs packet padding.
func pad(packet []byte) (padded []byte) {
	// get closest divisible by 64 to <packet-len> + 1 byte for 0x80.
	minQuestionSize := len(packet) + 1 + (64 - (len(packet)+1)%64)

	// padded size can't be less than minUDPQuestionSize.
	if minUDPQuestionSize > minQuestionSize {
		minQuestionSize = minUDPQuestionSize
	}

	packet = append(packet, 0x80)
	for len(packet) < minQuestionSize {
		packet = append(packet, 0)
	}

	return packet
}

// unpad removes padding bytes from packet.
func unpad(packet []byte) (unpadded []byte, err error) {
	for i := len(packet); ; {
		if i == 0 {
			return nil, ErrInvalidPadding
		}

		i--
		if packet[i] == 0x80 {
			if i < minDNSPacketSize {
				return nil, ErrInvalidPadding
			}

			return packet[:i], nil
		} else if packet[i] != 0x00 {
			return nil, ErrInvalidPadding
		}
	}
}

// computeSharedKey computes a shared key.  secretKey and publicKey must not
// be nil.
func computeSharedKey(
	cryptoConstruction CryptoConstruction,
	secretKey *[KeySize]byte,
	publicKey *[KeySize]byte,
) (sharedKey [KeySize]byte, err error) {
	switch cryptoConstruction {
	case XChacha20Poly1305:
		sharedKey, err = xsecretbox.SharedKey(*secretKey, *publicKey)
		if err != nil {
			return sharedKey, err
		}

		return sharedKey, nil
	case XSalsa20Poly1305:
		sharedKey = [SharedKeySize]byte{}
		box.Precompute(&sharedKey, publicKey, secretKey)

		return sharedKey, nil
	}

	return [KeySize]byte{}, ErrESVersion
}

// dddToByte converts a slice of three ASCII digits into a byte value.
func dddToByte(s []byte) (res byte) {
	return (s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0')
}

const (
	// escapedByteSmall contains escaped representations of bytes from 0x00
	// to 0x1F.
	escapedByteSmall = "" +
		`\000\001\002\003\004\005\006\007\008\009` +
		`\010\011\012\013\014\015\016\017\018\019` +
		`\020\021\022\023\024\025\026\027\028\029` +
		`\030\031`

	// escapedByteLarge contains escaped representations of bytes from 0x7F
	// to 0xFF.
	escapedByteLarge = `\127\128\129` +
		`\130\131\132\133\134\135\136\137\138\139` +
		`\140\141\142\143\144\145\146\147\148\149` +
		`\150\151\152\153\154\155\156\157\158\159` +
		`\160\161\162\163\164\165\166\167\168\169` +
		`\170\171\172\173\174\175\176\177\178\179` +
		`\180\181\182\183\184\185\186\187\188\189` +
		`\190\191\192\193\194\195\196\197\198\199` +
		`\200\201\202\203\204\205\206\207\208\209` +
		`\210\211\212\213\214\215\216\217\218\219` +
		`\220\221\222\223\224\225\226\227\228\229` +
		`\230\231\232\233\234\235\236\237\238\239` +
		`\240\241\242\243\244\245\246\247\248\249` +
		`\250\251\252\253\254\255`
)

// escapeByte returns the \DDD escaping of b which must satisfy
// b < ' ' || b > '~'.
func escapeByte(b byte) (escaped string) {
	if b < ' ' {
		return escapedByteSmall[b*4 : b*4+4]
	}

	b -= '~' + 1

	// The cast here is needed as b*4 may overflow byte.
	return escapedByteLarge[int(b)*4 : int(b)*4+4]
}

// packTxtString packs a TXT string by escaping special characters.  buf must
// not be nil.
func packTxtString(buf []byte) (packed string) {
	var out strings.Builder
	out.Grow(3 + len(buf))
	for i := 0; i < len(buf); i++ {
		b := buf[i]
		switch {
		case b == '"' || b == '\\':
			out.WriteByte('\\')
			out.WriteByte(b)
		case b < ' ' || b > '~':
			out.WriteString(escapeByte(b))
		default:
			out.WriteByte(b)
		}
	}

	return out.String()
}

// unpackTxtString unpacks a TXT string by unescaping special characters.
func unpackTxtString(s string) (msg []byte) {
	bs := []byte(s)
	msg = make([]byte, 0)
	for i := 0; i < len(bs); i++ {
		if bs[i] != '\\' {
			msg = append(msg, bs[i])

			continue
		}

		i++
		if i == len(bs) {
			break
		}

		if i+2 < len(bs) && isDigitSequence(bs[i:i+3]) {
			msg = append(msg, dddToByte(bs[i:]))
			i += 2

			continue
		}

		msg = append(msg, unescape(bs[i]))
	}

	return msg
}

// unescape returns corresponding escape-sequence by its char.  If b is not part
// of any escape sequence, b is being returned.
func unescape(b byte) (escaped byte) {
	switch b {
	case 't':
		return '\t'
	case 'r':
		return '\r'
	case 'n':
		return '\n'
	default:
		return b
	}
}

// isDigitSequence returns true if every character in sequence is numeric.
func isDigitSequence(sequence []byte) (ok bool) {
	for _, c := range sequence {
		if c < '0' || c > '9' {
			return false
		}
	}

	return true
}

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

// isConnClosed checks if the error signals a closed server connection.
func isConnClosed(err error) (ok bool) {
	if err == nil {
		return false
	}

	nerr, ok := err.(*net.OpError)
	if !ok {
		return false
	}

	if strings.Contains(nerr.Err.Error(), "use of closed network connection") {
		return true
	}

	return false
}
