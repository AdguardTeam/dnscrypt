package dnscrypt

import (
	"net"
	"time"

	"github.com/miekg/dns"
)

const defaultTimeout = 10 * time.Second

// Handler describes DNS handlers.
type Handler interface {
	// ServeDNS handles DNS requests.  rw and r must not be nil.
	//
	// TODO(f.setrakov): Add context.
	ServeDNS(rw ResponseWriter, r *dns.Msg) (err error)
}

// ResponseWriter describes response writer for various protocols.
type ResponseWriter interface {
	// LocalAddr returns local socket address.
	LocalAddr() (addr net.Addr)

	// RemoteAddr returns remote client socket address.
	RemoteAddr() (addr net.Addr)

	// WriteMsg writes response message to the client.  m must not be nil.
	WriteMsg(m *dns.Msg) (err error)
}

// defaultHandler is a default implementation of the [Handler] interface.
type defaultHandler struct {
	udpClient *dns.Client
	tcpClient *dns.Client
	addr      string
}

// ServeDNS implements the [Handler] interface for *defaultHandler.
func (h *defaultHandler) ServeDNS(rw ResponseWriter, r *dns.Msg) (err error) {
	res, _, err := h.udpClient.Exchange(r, h.addr)
	if err != nil {
		return err
	}

	if res.Truncated {
		res, _, err = h.tcpClient.Exchange(r, h.addr)
		if err != nil {
			return err
		}
	}

	return rw.WriteMsg(res)
}

// DefaultHandler is the default [Handler] implementation that is used by
// [Server] if custom handler is not configured.
var DefaultHandler Handler = &defaultHandler{
	udpClient: &dns.Client{
		Net:     string(ProtoUDP),
		Timeout: defaultTimeout,
	},
	tcpClient: &dns.Client{
		Net:     string(ProtoTCP),
		Timeout: defaultTimeout,
	},
	addr: "94.140.14.140:53",
}
