package dnscrypt_test

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// testTimeout is a common timeout for tests.
	testTimeout = time.Second

	// testTTL is a common DNS record TTL value that is used for testing.
	testTTL = 5 * time.Minute

	// testHostname is a common hostname for tests.
	testHostname = "example.org"

	// prefixedHostame is a common hostname with DNSCrypt provider prefix.
	prefixedHostname = dnscrypt.DNSCryptV2Prefix + testHostname

	// testFQDN is a common FQDN value for tests.  It is FQDN for
	// [testHostname].
	testFQDN = testHostname + "."
)

var (
	// testLogger is a common logger for tests.
	testLogger = slogutil.NewDiscardLogger()

	// testIPv4 is a common IPv4 address that is used for testing.
	testIPv4 = netip.MustParseAddr("192.0.2.0")
)

// newTestClient *Client initialized with fields from conf.  All the missing
// values will be replaced with defaults.
func newTestClient(conf *dnscrypt.ClientConfig) (c *dnscrypt.Client) {
	conf = cmp.Or(conf, &dnscrypt.ClientConfig{})

	return dnscrypt.NewClient(&dnscrypt.ClientConfig{
		Logger:  cmp.Or(conf.Logger, testLogger),
		Proto:   cmp.Or(conf.Proto, dnscrypt.ProtoUDP),
		UDPSize: cmp.Or(conf.UDPSize, dns.MinMsgSize),
	})
}

// createTestMessage is a helper that returns DNS message with default
// parameters.
func createTestMessage() (msg *dns.Msg) {
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{{
		Name:   testFQDN,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}

	return &req
}

// assertTestMessageResponse verifies that the reply matches the default
// expectations.
func assertTestMessageResponse(tb testing.TB, reply *dns.Msg) {
	tb.Helper()

	require.NotNil(tb, reply)
	require.Len(tb, reply.Answer, 1)

	a := testutil.RequireTypeAssert[*dns.A](tb, reply.Answer[0])

	assert.Equal(tb, net.IP(testIPv4.AsSlice()), a.A)
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

	rc, err := dnscrypt.GenerateResolverConfig(prefixedHostname, nil, testTTL)
	require.NoError(tb, err)

	resolverPk, err = dnscrypt.HexDecodeKey(rc.PublicKey)
	require.NoError(tb, err)

	cert, err = rc.NewCert()
	require.NoError(tb, err)

	s, err := dnscrypt.NewServer(&dnscrypt.ServerConfig{
		Logger:       testLogger,
		ProviderName: rc.ProviderName,
		ResolverCert: cert,
		Handler:      handler,
		Addr:         netip.AddrPortFrom(netutil.IPv4Localhost(), 0),
		Proto:        proto,
	})
	require.NoError(tb, err)
	servicetest.RequireRun(tb, s, testTimeout)

	return s, resolverPk, cert
}

// testHandler is the default implementation of the [dnscrypt.Handler] for
// tests.
type testHandler struct{}

// ServeDNS implements the [dnscrypt.Handler] interface for *testHandler.
func (h *testHandler) ServeDNS(
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
		Ttl:    uint32(testTTL.Seconds()),
		Class:  dns.ClassINET,
	}
	// First record is from Google DNS.
	answer.A = testIPv4.AsSlice()
	res.Answer = append(res.Answer, answer)

	return rw.WriteMsg(ctx, res)
}

// testLargeMsgHandler is the implementation of the [dnscrypt.Handler] interface
// that returns a huge response used for testing message truncation.
//
// TODO(f.setrakov): Add a mock implementation in internal/dnscrypttest.
type testLargeMsgHandler struct{}

// type check
var _ dnscrypt.Handler = (*testLargeMsgHandler)(nil)

// ServeDNS implements the [dnscrypt.Handler] interface for
// *testLargeMsgHandler.
func (h *testLargeMsgHandler) ServeDNS(
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
			Ttl:    uint32(testTTL.Seconds()),
			Class:  dns.ClassINET,
		}

		answer.A = net.IPv4(127, 0, 0, byte(i))
		res.Answer = append(res.Answer, answer)
	}

	res.Compress = true

	return rw.WriteMsg(ctx, res)
}
