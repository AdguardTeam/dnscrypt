package dnscrypt_test

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/dnscrypt/internal/dnscrypttest"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// prefixedHostame is a [dnscrypttest.Hostname] with DNSCrypt provider prefix.
const prefixedHostname = dnscrypt.DNSCryptV2Prefix + dnscrypttest.Hostname

// newTestClient *Client initialized with fields from conf.  All the missing
// values will be replaced with defaults.
func newTestClient(conf *dnscrypt.ClientConfig) (c *dnscrypt.Client) {
	conf = cmp.Or(conf, &dnscrypt.ClientConfig{})

	return dnscrypt.NewClient(&dnscrypt.ClientConfig{
		Logger:  cmp.Or(conf.Logger, dnscrypttest.Logger),
		Proto:   cmp.Or(conf.Proto, dnscrypt.ProtoUDP),
		UDPSize: cmp.Or(conf.UDPSize, dns.MinMsgSize),
	})
}

// newTestServerStamp creates a dnsstamps.ServerStamp for the given server,
// proto and resolver public key.
func newTestServerStamp(
	srv *dnscrypt.Server,
	resolverPk ed25519.PublicKey,
) (stamp *dnsstamps.ServerStamp) {
	return &dnsstamps.ServerStamp{
		ServerPk:      resolverPk,
		ProviderName:  prefixedHostname,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
		ServerAddrStr: srv.LocalAddr().String(),
	}
}

// newTestServer returns properly initialized *testServer.
func newTestServer(
	tb testing.TB,
	handler dnscrypt.Handler,
	proto dnscrypt.Proto,
) (server *dnscrypt.Server, resolverPk ed25519.PublicKey, cert *dnscrypt.Certificate) {
	tb.Helper()

	rc, err := dnscrypt.GenerateResolverConfig(prefixedHostname, nil, dnscrypttest.TTL)
	require.NoError(tb, err)

	resolverPk, err = dnscrypt.HexDecodeKey(rc.PublicKey)
	require.NoError(tb, err)

	cert, err = rc.NewCert()
	require.NoError(tb, err)

	s, err := dnscrypt.NewServer(&dnscrypt.ServerConfig{
		Logger:       dnscrypttest.Logger,
		ProviderName: rc.ProviderName,
		ResolverCert: cert,
		Handler:      handler,
		Addr:         netip.AddrPortFrom(netutil.IPv4Localhost(), 0),
		Proto:        proto,
	})
	require.NoError(tb, err)
	servicetest.RequireRun(tb, s, dnscrypttest.Timeout)

	return s, resolverPk, cert
}

// testHandler is a [dnscrypt.HandlerFunc] that responds with common test data.
func testHandler(
	ctx context.Context,
	rw dnscrypt.ResponseWriter,
	r *dns.Msg,
) (err error) {
	res := &dns.Msg{}
	res.SetReply(r)

	answer := &dns.A{}
	answer.Hdr = dns.RR_Header{
		Name:   r.Question[0].Name,
		Rrtype: dns.TypeA,
		Ttl:    uint32(dnscrypttest.TTL.Seconds()),
		Class:  dns.ClassINET,
	}
	// First record is from Google DNS.
	answer.A = dnscrypttest.IPv4.AsSlice()
	res.Answer = append(res.Answer, answer)

	return rw.WriteMsg(ctx, res)
}

// type check
var _ dnscrypt.HandlerFunc = testHandler

// testLargeMsgHandler is the [dnscrypt.HandlerFunc] that returns a huge
// response used for testing message truncation.
//
// TODO(f.setrakov): Add a mock implementation in internal/dnscrypttest.
func testLargeMsgHandler(
	ctx context.Context,
	rw dnscrypt.ResponseWriter,
	r *dns.Msg,
) (err error) {
	res := &dns.Msg{}
	res.SetReply(r)

	for i := 0; i < 64; i++ {
		answer := &dns.A{}
		answer.Hdr = dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeA,
			Ttl:    uint32(dnscrypttest.TTL.Seconds()),
			Class:  dns.ClassINET,
		}

		answer.A = net.IPv4(127, 0, 0, byte(i))
		res.Answer = append(res.Answer, answer)
	}

	res.Compress = true

	return rw.WriteMsg(ctx, res)
}

// type check
var _ dnscrypt.HandlerFunc = testLargeMsgHandler
