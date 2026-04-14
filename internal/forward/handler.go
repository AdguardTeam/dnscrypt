package forward

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/miekg/dns"
)

// HandlerConfig is the configuration structure for [*Handler].
type HandlerConfig struct {
	// Client is used to execute DNS requests.  It must not be nil.
	Client *dns.Client

	// Address is the upstream address to which requests will be forwarded.  It
	// must not be empty.
	Address netip.AddrPort
}

// Handler is the [dnscrypt.Handler] implementation that forwards DNS requests
// to the configured upstream.
type Handler struct {
	client *dns.Client
	addr   string
}

// NewHandler returns properly initialized *Handler.  c must be non-nil and
// valid.
func NewHandler(c *HandlerConfig) (h *Handler) {
	return &Handler{
		client: c.Client,
		addr:   c.Address.String(),
	}
}

// type check
var _ dnscrypt.Handler = (*Handler)(nil)

// ServeDNS implements the [dnscrypt.Handler] interface for *Handler.
func (h *Handler) ServeDNS(
	ctx context.Context,
	rw dnscrypt.ResponseWriter,
	r *dns.Msg,
) (err error) {
	res, _, err := h.client.ExchangeContext(ctx, r, h.addr)
	if err != nil {
		return fmt.Errorf("exchanging: %w", err)
	}

	return rw.WriteMsg(ctx, res)
}
