package dnscrypttest

import (
	"net"
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NewDNSMessage is a helper that returns DNS message with default parameters.
func NewDNSMessage() (msg *dns.Msg) {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   FQDN,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}
}

// AssertDefaultDNSMessageResponse is a helper that verifies that the reply
// matches the default expectations.
func AssertDefaultDNSMessageResponse(tb testing.TB, reply *dns.Msg) {
	tb.Helper()

	require.NotNil(tb, reply)
	require.Len(tb, reply.Answer, 1)

	a := testutil.RequireTypeAssert[*dns.A](tb, reply.Answer[0])

	assert.Equal(tb, net.IP(IPv4.AsSlice()), a.A)
}
