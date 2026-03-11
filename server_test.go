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
	require.NoError(t, srv.Close())
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
	t.Cleanup(func() {
		require.NoError(t, srv.Close())
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
	t.Cleanup(func() {
		require.NoError(t, srv.Close())
	})

	client := &Client{
		Timeout: 1 * time.Second,
		Proto:   ProtoUDP,
	}
	serverAddr := fmt.Sprintf("127.0.0.1:%d", srv.UDPAddr().Port)
	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: serverAddr,
		ServerPk:      srv.resolverPk,
		ProviderName:  srv.server.ProviderName,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}
	ri, err := client.DialStamp(stamp)
	require.NoError(t, err)
	require.NotNil(t, ri)

	m := createTestMessage()
	res, err := client.Exchange(m, ri)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, dns.RcodeSuccess, res.Rcode)
	require.Len(t, res.Answer, 0)
	require.True(t, res.Truncated)
}

func TestServer_UDPEDNS0_NoTruncate(t *testing.T) {
	srv := newTestServer(t, &testLargeMsgHandler{})
	t.Cleanup(func() {
		require.NoError(t, srv.Close())
	})

	client := &Client{
		Timeout: 1 * time.Second,
		Proto:   ProtoUDP,
		UDPSize: 7000,
	}
	serverAddr := fmt.Sprintf("127.0.0.1:%d", srv.UDPAddr().Port)
	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: serverAddr,
		ServerPk:      srv.resolverPk,
		ProviderName:  srv.server.ProviderName,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}
	ri, err := client.DialStamp(stamp)
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
	res, err := client.Exchange(m, ri)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, dns.RcodeSuccess, res.Rcode)
	require.Len(t, res.Answer, 64)
	require.False(t, res.Truncated)
}

func testServerServeCert(t *testing.T, proto Proto) {
	srv := newTestServer(t, &testHandler{})
	t.Cleanup(func() {
		require.NoError(t, srv.Close())
	})

	client := &Client{
		Proto:   proto,
		Timeout: 1 * time.Second,
	}

	serverAddr := fmt.Sprintf("127.0.0.1:%d", srv.UDPAddr().Port)
	if proto == ProtoTCP {
		serverAddr = fmt.Sprintf("127.0.0.1:%d", srv.TCPAddr().Port)
	}

	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: serverAddr,
		ServerPk:      srv.resolverPk,
		ProviderName:  srv.server.ProviderName,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}
	ri, err := client.DialStamp(stamp)
	require.NoError(t, err)
	require.NotNil(t, ri)

	require.Equal(t, ri.ProviderName, srv.server.ProviderName)
	require.True(t, bytes.Equal(srv.server.ResolverCert.ClientMagic[:], ri.ResolverCert.ClientMagic[:]))
	require.Equal(t, srv.server.ResolverCert.EsVersion, ri.ResolverCert.EsVersion)
	require.Equal(t, srv.server.ResolverCert.Signature, ri.ResolverCert.Signature)
	require.Equal(t, srv.server.ResolverCert.NotBefore, ri.ResolverCert.NotBefore)
	require.Equal(t, srv.server.ResolverCert.NotAfter, ri.ResolverCert.NotAfter)
	require.True(t, bytes.Equal(srv.server.ResolverCert.ResolverPk[:], ri.ResolverCert.ResolverPk[:]))
	require.True(t, bytes.Equal(srv.server.ResolverCert.ResolverPk[:], ri.ResolverCert.ResolverPk[:]))
}

// testServerRespondMessages is a helper that verifies that the [testServer]
// responds to the default messages as expected.  The server will use the given
// protocol and [testHandler].
func testServerRespondMessages(tb testing.TB, proto Proto) {
	tb.Helper()

	srv := newTestServer(tb, &testHandler{})
	testutil.CleanupAndRequireSuccess(tb, srv.Close)
	testThisServerRespondMessages(tb, proto, srv)
}

// testThisServerRespondMessages is a helper that verifies that the given server
// responds to the default messages as expected.
func testThisServerRespondMessages(tb testing.TB, proto Proto, srv *testServer) {
	tb.Helper()

	client := &Client{
		Timeout: 1 * time.Second,
		Proto:   proto,
	}

	serverAddr := fmt.Sprintf("127.0.0.1:%d", srv.UDPAddr().Port)
	if proto == ProtoTCP {
		serverAddr = fmt.Sprintf("127.0.0.1:%d", srv.TCPAddr().Port)
	}

	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: serverAddr,
		ServerPk:      srv.resolverPk,
		ProviderName:  srv.server.ProviderName,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}
	ri, err := client.DialStamp(stamp)
	require.NoError(tb, err)
	require.NotNil(tb, ri)

	var conn net.Conn
	conn, err = net.Dial(string(proto), stamp.ServerAddrStr)
	require.NoError(tb, err)

	for i := 0; i < 10; i++ {
		m := createTestMessage()

		var res *dns.Msg
		res, err = client.ExchangeConn(conn, m, ri)
		require.NoError(tb, err)
		assertTestMessageResponse(tb, res)
	}
}

// testServer is the implementation of the [ServerDNSCrypt] interface for tests.
type testServer struct {
	tcpListen  net.Listener
	server     *Server
	udpConn    *net.UDPConn
	resolverPk ed25519.PublicKey
}

// TCPAddr implements the [ServerDNSCrypt] interface for *testServer.
func (s *testServer) TCPAddr() (addr *net.TCPAddr) {
	return s.tcpListen.Addr().(*net.TCPAddr)
}

// UDPAddr implements the [ServerDNSCrypt] interface for *testServer.
func (s *testServer) UDPAddr() (addr *net.UDPAddr) {
	return s.udpConn.LocalAddr().(*net.UDPAddr)
}

// Close closes server connections and runs shutdown.
func (s *testServer) Close() (err error) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
	defer cancel()

	err = s.server.Shutdown(ctx)
	_ = s.udpConn.Close()
	_ = s.tcpListen.Close()

	return err
}

// newTestServer returns properly initialized *testServer.
func newTestServer(t require.TestingT, handler Handler) (server *testServer) {
	rc, err := GenerateResolverConfig("example.org", nil)
	require.NoError(t, err)
	cert, err := rc.CreateCert()
	require.NoError(t, err)

	s := &Server{
		ProviderName: rc.ProviderName,
		ResolverCert: cert,
		Handler:      handler,
	}

	privateKey, err := HexDecodeKey(rc.PrivateKey)
	require.NoError(t, err)
	publicKey := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	srv := &testServer{
		server:     s,
		resolverPk: publicKey,
	}

	srv.tcpListen, err = net.ListenTCP(string(ProtoTCP), &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	require.NoError(t, err)
	srv.udpConn, err = net.ListenUDP(string(ProtoUDP), &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	require.NoError(t, err)

	go func() {
		_ = s.ServeUDP(srv.udpConn)
	}()
	go func() {
		_ = s.ServeTCP(srv.tcpListen)
	}()

	return srv
}

// testHandler is the default implementation of the [Handler] for tests.
type testHandler struct{}

// ServeDNS implements the [Handler] interface for *testHandler.
func (h *testHandler) ServeDNS(rw ResponseWriter, r *dns.Msg) (err error) {
	res := new(dns.Msg)
	res.SetReply(r)

	answer := new(dns.A)
	answer.Hdr = dns.RR_Header{
		Name:   r.Question[0].Name,
		Rrtype: dns.TypeA,
		Ttl:    300,
		Class:  dns.ClassINET,
	}
	// First record is from Google DNS.
	answer.A = net.IPv4(8, 8, 8, 8)
	res.Answer = append(res.Answer, answer)

	return rw.WriteMsg(res)
}

// testLargeMsgHandler is the implementation of the [Handler] interface that
// returns a huge response used for testing message truncation.
type testLargeMsgHandler struct{}

// ServeDNS implements the [Handler] interface for *testLargeMsgHandler.
func (h *testLargeMsgHandler) ServeDNS(rw ResponseWriter, r *dns.Msg) (err error) {
	res := new(dns.Msg)
	res.SetReply(r)

	for i := 0; i < 64; i++ {
		answer := new(dns.A)
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

	return rw.WriteMsg(res)
}
