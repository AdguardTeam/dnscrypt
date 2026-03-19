package dnscrypt

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// defaultTimeout is the timeout for [DefaultHandler].
const defaultTimeout = 10 * time.Second

// Handler describes DNS handlers.
type Handler interface {
	// ServeDNS handles DNS requests.  rw and r must not be nil.
	ServeDNS(ctx context.Context, rw ResponseWriter, r *dns.Msg) (err error)
}

// ResponseWriter describes response writer for various protocols.
type ResponseWriter interface {
	// LocalAddr returns local socket address.
	LocalAddr() (addr net.Addr)

	// RemoteAddr returns remote client socket address.
	RemoteAddr() (addr net.Addr)

	// WriteMsg writes response message to the client.  m must not be nil.
	WriteMsg(ctx context.Context, m *dns.Msg) (err error)
}

// defaultHandler is a default implementation of the [Handler] interface.
type defaultHandler struct {
	udpClient *dns.Client
	tcpClient *dns.Client
	addr      string
}

// ServeDNS implements the [Handler] interface for *defaultHandler.
func (h *defaultHandler) ServeDNS(ctx context.Context, rw ResponseWriter, r *dns.Msg) (err error) {
	res, _, err := h.udpClient.ExchangeContext(ctx, r, h.addr)
	if err != nil {
		return fmt.Errorf("exchanging udp message: %w", err)
	}

	if res.Truncated {
		res, _, err = h.tcpClient.ExchangeContext(ctx, r, h.addr)
		if err != nil {
			return fmt.Errorf("exchanging tcp message: %w", err)
		}
	}

	return rw.WriteMsg(ctx, res)
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
