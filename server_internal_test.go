package dnscrypt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestServer_Shutdown(t *testing.T) {
	n := runtime.GOMAXPROCS(1)
	t.Cleanup(func() {
		runtime.GOMAXPROCS(n)
	})
	srv := newTestServer(t, &testHandler{})
	// Serve* methods are called in different goroutines
	// give them at least a moment to actually start the server
	time.Sleep(10 * time.Millisecond)
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	require.NoError(t, srv.Shutdown(ctx))
}

func TestServer_UDPServeCert(t *testing.T) {
	testServerServeCert(t, ProtoUDP)
}

func TestServer_TCPServeCert(t *testing.T) {
	testServerServeCert(t, ProtoTCP)
}

func TestServer_UDPRespondMessages(t *testing.T) {
	testServerRespondMessages(t, ProtoUDP)
}

func TestServer_TCPRespondMessages(t *testing.T) {
	testServerRespondMessages(t, ProtoTCP)
}

func TestServer_ReadTimeout(t *testing.T) {
	srv := newTestServer(t, &testHandler{})
	ctx := testutil.ContextWithTimeout(t, 3*time.Second)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return srv.Shutdown(ctx)
	})
	// Sleep for "defaultReadTimeout" before trying to shutdown the server.  The
	// point is to make sure readTimeout is properly handled by the "Serve*"
	// goroutines and they don't finish their work unexpectedly.
	time.Sleep(defaultReadTimeout)
	testThisServerRespondMessages(t, ProtoUDP, srv)
	testThisServerRespondMessages(t, ProtoTCP, srv)
}

func TestServer_UDPTruncateMessage(t *testing.T) {
	srv := newTestServer(t, &testLargeMsgHandler{})
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return srv.Shutdown(ctx)
	})

	client := newTestClient(&ClientConfig{Proto: ProtoUDP})
	serverAddr := fmt.Sprintf("127.0.0.1:%d", srv.UDPAddr().Port)
	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: serverAddr,
		ServerPk:      srv.resolverPk,
		ProviderName:  srv.server.providerName,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}
	ri, err := client.DialStampContext(ctx, stamp)
	require.NoError(t, err)
	require.NotNil(t, ri)

	m := createTestMessage()
	res, err := client.ExchangeContext(ctx, m, ri)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, dns.RcodeSuccess, res.Rcode)
	require.Len(t, res.Answer, 0)
	require.True(t, res.Truncated)
}

func TestServer_UDPEDNS0_NoTruncate(t *testing.T) {
	srv := newTestServer(t, &testLargeMsgHandler{})
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return srv.Shutdown(ctx)
	})

	client := newTestClient(&ClientConfig{
		Proto:   ProtoUDP,
		UDPSize: 7000,
	})
	serverAddr := fmt.Sprintf("127.0.0.1:%d", srv.UDPAddr().Port)
	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: serverAddr,
		ServerPk:      srv.resolverPk,
		ProviderName:  srv.server.providerName,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}
	ri, err := client.DialStampContext(ctx, stamp)
	require.NoError(t, err)
	require.NotNil(t, ri)

	m := createTestMessage()
	m.Extra = append(m.Extra, &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  2000,
		},
	})
	res, err := client.ExchangeContext(ctx, m, ri)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, dns.RcodeSuccess, res.Rcode)
	require.Len(t, res.Answer, 64)
	require.False(t, res.Truncated)
}

func testServerServeCert(t *testing.T, proto Proto) {
	srv := newTestServer(t, &testHandler{})
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return srv.Shutdown(ctx)
	})

	client := newTestClient(&ClientConfig{Proto: proto})

	serverAddr := fmt.Sprintf("127.0.0.1:%d", srv.UDPAddr().Port)
	if proto == ProtoTCP {
		serverAddr = fmt.Sprintf("127.0.0.1:%d", srv.TCPAddr().Port)
	}

	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: serverAddr,
		ServerPk:      srv.resolverPk,
		ProviderName:  srv.server.providerName,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}

	ri, err := client.DialStampContext(ctx, stamp)
	require.NoError(t, err)
	require.NotNil(t, ri)

	require.Equal(t, ri.ProviderName, srv.server.providerName)
	require.True(t, bytes.Equal(srv.server.resolverCert.ClientMagic[:], ri.ResolverCert.ClientMagic[:]))
	require.Equal(t, srv.server.resolverCert.EsVersion, ri.ResolverCert.EsVersion)
	require.Equal(t, srv.server.resolverCert.Signature, ri.ResolverCert.Signature)
	require.Equal(t, srv.server.resolverCert.NotBefore, ri.ResolverCert.NotBefore)
	require.Equal(t, srv.server.resolverCert.NotAfter, ri.ResolverCert.NotAfter)
	require.True(t, bytes.Equal(srv.server.resolverCert.ResolverPk[:], ri.ResolverCert.ResolverPk[:]))
	require.True(t, bytes.Equal(srv.server.resolverCert.ResolverPk[:], ri.ResolverCert.ResolverPk[:]))
}

// testServerRespondMessages is a helper that verifies that the [testServer]
// responds to the default messages as expected.  The server will use the given
// protocol and [testHandler].
func testServerRespondMessages(tb testing.TB, proto Proto) {
	tb.Helper()

	srv := newTestServer(tb, &testHandler{})
	ctx := testutil.ContextWithTimeout(tb, testTimeout)
	testutil.CleanupAndRequireSuccess(tb, func() (err error) {
		return srv.Shutdown(ctx)
	})
	testThisServerRespondMessages(tb, proto, srv)
}

// testThisServerRespondMessages is a helper that verifies that the given server
// responds to the default messages as expected.
func testThisServerRespondMessages(tb testing.TB, proto Proto, srv *testServer) {
	tb.Helper()

	client := newTestClient(&ClientConfig{Proto: proto})

	serverAddr := fmt.Sprintf("127.0.0.1:%d", srv.UDPAddr().Port)
	if proto == ProtoTCP {
		serverAddr = fmt.Sprintf("127.0.0.1:%d", srv.TCPAddr().Port)
	}

	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: serverAddr,
		ServerPk:      srv.resolverPk,
		ProviderName:  srv.server.providerName,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}

	ctx := testutil.ContextWithTimeout(tb, testTimeout)
	ri, err := client.DialStampContext(ctx, stamp)
	require.NoError(tb, err)
	require.NotNil(tb, ri)

	var conn net.Conn
	conn, err = net.Dial(string(proto), stamp.ServerAddrStr)
	require.NoError(tb, err)

	for i := 0; i < 10; i++ {
		m := createTestMessage()

		var res *dns.Msg
		res, err = client.ExchangeConnContext(ctx, conn, m, ri)
		require.NoError(tb, err)
		assertTestMessageResponse(tb, res)
	}
}

// testServer is a DNSCrypt server for testing
type testServer struct {
	tcpListen  net.Listener
	server     *Server
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
func newTestServer(tb testing.TB, handler Handler) (server *testServer) {
	rc, err := GenerateResolverConfig("example.org", nil)
	require.NoError(tb, err)
	cert, err := rc.CreateCert()
	require.NoError(tb, err)

	s := NewServer(&ServerConfig{
		Logger:       testLogger,
		ProviderName: rc.ProviderName,
		ResolverCert: cert,
		Handler:      handler,
	})

	privateKey, err := HexDecodeKey(rc.PrivateKey)
	require.NoError(tb, err)
	publicKey := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	srv := &testServer{
		server:     s,
		resolverPk: publicKey,
	}

	srv.tcpListen, err = net.ListenTCP(string(ProtoTCP), &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	require.NoError(tb, err)
	srv.udpConn, err = net.ListenUDP(string(ProtoUDP), &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	require.NoError(tb, err)

	ctx := testutil.ContextWithTimeout(tb, testTimeout)

	go func() {
		_ = s.ServeUDP(ctx, srv.udpConn)
	}()
	go func() {
		_ = s.ServeTCP(ctx, srv.tcpListen)
	}()

	return srv
}

// testHandler is the default implementation of the [Handler] for tests.
type testHandler struct{}

// ServeDNS implements the [Handler] interface for *testHandler.
func (h *testHandler) ServeDNS(ctx context.Context, rw ResponseWriter, r *dns.Msg) (err error) {
	res := &dns.Msg{}
	res.SetReply(r)

	answer := &dns.A{}
	answer.Hdr = dns.RR_Header{
		Name:   r.Question[0].Name,
		Rrtype: dns.TypeA,
		Ttl:    300,
		Class:  dns.ClassINET,
	}
	// First record is from Google DNS.
	answer.A = net.IPv4(8, 8, 8, 8)
	res.Answer = append(res.Answer, answer)

	return rw.WriteMsg(ctx, res)
}

// testLargeMsgHandler is the implementation of the [Handler] interface that
// returns a huge response used for testing message truncation.
type testLargeMsgHandler struct{}

// ServeDNS implements the [Handler] interface for *testLargeMsgHandler.
func (h *testLargeMsgHandler) ServeDNS(
	ctx context.Context,
	rw ResponseWriter,
	r *dns.Msg,
) (err error) {
	res := &dns.Msg{}
	res.SetReply(r)

	for i := 0; i < 64; i++ {
		answer := &dns.A{}
		answer.Hdr = dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeA,
			Ttl:    300,
			Class:  dns.ClassINET,
		}
		answer.A = net.IPv4(127, 0, 0, byte(i))
		res.Answer = append(res.Answer, answer)
	}

	res.Compress = true

	return rw.WriteMsg(ctx, res)
}

func BenchmarkServeUDP(b *testing.B) {
	benchmarkServe(b, ProtoUDP)

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/dnscrypt
	//	cpu: Apple M4 Pro
	//	BenchmarkServeUDP-14    	    9333	    126311 ns/op	    6681 B/op	      61 allocs/op
	//	PASS
	//	ok  	github.com/AdguardTeam/dnscrypt	2.052s
}

func BenchmarkServeTCP(b *testing.B) {
	benchmarkServe(b, ProtoTCP)
	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/dnscrypt
	//	cpu: Apple M4 Pro
	//	BenchmarkServeTCP-14    	   10113	    115749 ns/op	    5568 B/op	      65 allocs/op
}

// benchmarkServe is a helper that benches [testServer] with given protocol.
func benchmarkServe(b *testing.B, proto Proto) {
	srv := newTestServer(b, &testHandler{})
	ctx := testutil.ContextWithTimeout(b, testTimeout)
	testutil.CleanupAndRequireSuccess(b, func() (err error) {
		return srv.Shutdown(ctx)
	})

	client := newTestClient(&ClientConfig{Proto: proto})

	serverAddr := fmt.Sprintf("127.0.0.1:%d", srv.UDPAddr().Port)
	if proto == ProtoTCP {
		serverAddr = fmt.Sprintf("127.0.0.1:%d", srv.TCPAddr().Port)
	}

	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: serverAddr,
		ServerPk:      srv.resolverPk,
		ProviderName:  srv.server.providerName,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}
	ri, err := client.DialStampContext(ctx, stamp)
	require.NoError(b, err)
	require.NotNil(b, ri)

	conn, err := net.Dial(string(proto), stamp.ServerAddrStr)
	require.NoError(b, err)

	var resp *dns.Msg

	b.ReportAllocs()
	for b.Loop() {
		m := createTestMessage()

		resp, err = client.ExchangeConnContext(ctx, conn, m, ri)
		require.NoError(b, err)
		assertTestMessageResponse(b, resp)
	}
}
