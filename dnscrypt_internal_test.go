package dnscrypt_test

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// testTimeout is a common timeout for tests.
const testTimeout = time.Second

var (
	// testLogger is a common logger for tests.
	testLogger = slogutil.NewDiscardLogger()

	// testIPv4 is a common IPv4 address that is used for testing.
	testIPv4 = netip.MustParseAddr("192.0.2.0")

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
	require.Equal(tb, net.IP(testIPv4.AsSlice()), a.A)
}

// newTestServerStamp creates a dnsstamps.ServerStamp for the given test server
// and protocol.
func newTestServerStamp(srv *testServer, proto dnscrypt.Proto) (stamp *dnsstamps.ServerStamp) {
	stamp = &dnsstamps.ServerStamp{
		ServerPk:     srv.resolverPk,
		ProviderName: prefixedHostname,
		Proto:        dnsstamps.StampProtoTypeDNSCrypt,
	}

	if proto == dnscrypt.ProtoTCP {
		stamp.ServerAddrStr = fmt.Sprintf("%s:%d", netutil.IPv4Localhost(), srv.TCPAddr().Port)
	} else {
		stamp.ServerAddrStr = fmt.Sprintf("%s:%d", netutil.IPv4Localhost(), srv.UDPAddr().Port)
	}

	return stamp
}

// testServer is a DNSCrypt server for testing.
type testServer struct {
	tcpListen  net.Listener
	server     *dnscrypt.Server
	udpConn    *net.UDPConn
	resolverPk ed25519.PublicKey
}

// TCPAddr returns the server's TCP listening address.
func (s *testServer) TCPAddr() (addr *net.TCPAddr) {
	return s.tcpListen.Addr().(*net.TCPAddr)
}

// UDPAddr returns the server's UDP listening address.
func (s *testServer) UDPAddr() (addr *net.UDPAddr) {
	return s.udpConn.LocalAddr().(*net.UDPAddr)
}

// Shutdown implements the [service.Shutdowner] for *testServer.
func (s *testServer) Shutdown(ctx context.Context) (err error) {
	err = s.server.Shutdown(ctx)
	_ = s.udpConn.Close()
	_ = s.tcpListen.Close()

	return err
}

// newTestServer returns properly initialized *testServer.
func newTestServer(tb testing.TB, handler dnscrypt.Handler) (server *testServer, cert *dnscrypt.Cert) {
	tb.Helper()

	rc, err := dnscrypt.GenerateResolverConfig(prefixedHostname, nil)
	require.NoError(tb, err)
	cert, err = rc.CreateCert()
	require.NoError(tb, err)

	s, err := dnscrypt.NewServer(&dnscrypt.ServerConfig{
		Logger:       testLogger,
		ProviderName: rc.ProviderName,
		ResolverCert: cert,
		Handler:      handler,
	})
	require.NoError(tb, err)

	privateKey, err := dnscrypt.HexDecodeKey(rc.PrivateKey)
	require.NoError(tb, err)
	publicKey := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	srv := &testServer{
		server:     s,
		resolverPk: publicKey,
	}

	srv.tcpListen, err = net.ListenTCP(string(dnscrypt.ProtoTCP), &net.TCPAddr{IP: net.IPv4zero})
	require.NoError(tb, err)

	srv.udpConn, err = net.ListenUDP(string(dnscrypt.ProtoUDP), &net.UDPAddr{IP: net.IPv4zero})
	require.NoError(tb, err)

	ctx := testutil.ContextWithTimeout(tb, testTimeout)

	go func() {
		_ = s.ServeUDP(ctx, srv.udpConn)
	}()
	go func() {
		_ = s.ServeTCP(ctx, srv.tcpListen)
	}()

	testutil.CleanupAndRequireSuccess(tb, func() (err error) {
		return srv.Shutdown(ctx)
	})

	return srv, cert
}

// testHandler is the default implementation of the [Handler] for tests.
type testHandler struct{}

// ServeDNS implements the [Handler] interface for *testHandler.
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

// testLargeMsgHandler is the implementation of the [Handler] interface that
// returns a huge response used for testing message truncation.
//
// TODO(f.setrakov): Add a mock implementation in internal/dnscrypttest.
type testLargeMsgHandler struct{}

// ServeDNS implements the [Handler] interface for *testLargeMsgHandler.
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
