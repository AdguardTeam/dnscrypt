package dnscrypt_test

import (
	"crypto/ed25519"
	"net"
	"testing"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_UDPServeCert(t *testing.T) {
	t.Parallel()

	testServerServeCert(t, dnscrypt.ProtoUDP)
}

func TestServer_TCPServeCert(t *testing.T) {
	t.Parallel()

	testServerServeCert(t, dnscrypt.ProtoTCP)
}

func TestServer_UDPRespondMessages(t *testing.T) {
	t.Parallel()

	testServerRespondMessages(t, dnscrypt.ProtoUDP)
}

func TestServer_TCPRespondMessages(t *testing.T) {
	t.Parallel()

	testServerRespondMessages(t, dnscrypt.ProtoTCP)
}

func TestServer_UDPTruncateMessage(t *testing.T) {
	t.Parallel()

	srv, resolverPk, _ := newTestServer(t, &testLargeMsgHandler{}, dnscrypt.ProtoUDP)
	client := newTestClient(&dnscrypt.ClientConfig{Proto: dnscrypt.ProtoUDP})
	stamp := newTestServerStamp(srv, resolverPk)
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	ri, err := client.DialStampContext(ctx, *stamp)
	require.NoError(t, err)
	require.NotNil(t, ri)

	m := createTestMessage()
	res, err := client.ExchangeContext(ctx, m, ri)
	require.NoError(t, err)
	require.NotNil(t, res)

	assert.Equal(t, dns.RcodeSuccess, res.Rcode)
	assert.Len(t, res.Answer, 0)
	assert.True(t, res.Truncated)
}

func TestServer_UDPEDNS0_NoTruncate(t *testing.T) {
	t.Parallel()

	srv, resolverPk, _ := newTestServer(t, &testLargeMsgHandler{}, dnscrypt.ProtoUDP)
	client := newTestClient(&dnscrypt.ClientConfig{
		Proto:   dnscrypt.ProtoUDP,
		UDPSize: 7000,
	})
	stamp := newTestServerStamp(srv, resolverPk)
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	ri, err := client.DialStampContext(ctx, *stamp)
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

	assert.Equal(t, dns.RcodeSuccess, res.Rcode)
	assert.Len(t, res.Answer, 64)
	assert.False(t, res.Truncated)
}

// testServerServeCert is a helper that checks that the server running on the
// given protocol responds with a valid certificate.
func testServerServeCert(tb testing.TB, proto dnscrypt.Proto) {
	srv, resolverPk, cert := newTestServer(tb, &testLargeMsgHandler{}, proto)
	client := newTestClient(&dnscrypt.ClientConfig{Proto: proto})

	stamp := newTestServerStamp(srv, resolverPk)
	ctx := testutil.ContextWithTimeout(tb, testTimeout)
	ri, err := client.DialStampContext(ctx, *stamp)
	require.NoError(tb, err)
	require.NotNil(tb, ri)

	assert.Equal(tb, cert.ClientMagic, ri.ResolverCert.ClientMagic)
	assert.Equal(tb, cert.ESVersion, ri.ResolverCert.ESVersion)
	assert.Equal(tb, cert.NotBefore, ri.ResolverCert.NotBefore)
	assert.Equal(tb, cert.NotAfter, ri.ResolverCert.NotAfter)
	assert.Equal(tb, cert.ResolverPk, ri.ResolverCert.ResolverPk)
	assert.Equal(tb, cert.Serial, ri.ResolverCert.Serial)
	assert.Equal(tb, cert.Signature, ri.ResolverCert.Signature)
}

// testServerRespondMessages is a helper that verifies that the [testServer]
// responds to the default messages as expected.  The server will use the given
// protocol and [testHandler].
func testServerRespondMessages(tb testing.TB, proto dnscrypt.Proto) {
	tb.Helper()

	srv, resolverPk, _ := newTestServer(tb, &testHandler{}, proto)
	testThisServerRespondMessages(tb, proto, srv, resolverPk)
}

// testThisServerRespondMessages is a helper that verifies that the given server
// responds to the default messages as expected.
func testThisServerRespondMessages(
	tb testing.TB,
	proto dnscrypt.Proto,
	srv *dnscrypt.Server,
	resolverPk ed25519.PublicKey,
) {
	tb.Helper()

	client := newTestClient(&dnscrypt.ClientConfig{Proto: proto})
	stamp := newTestServerStamp(srv, resolverPk)

	ctx := testutil.ContextWithTimeout(tb, testTimeout)
	ri, err := client.DialStampContext(ctx, *stamp)
	require.NoError(tb, err)
	require.NotNil(tb, ri)

	var conn net.Conn
	conn, err = net.Dial(string(proto), stamp.ServerAddrStr)
	require.NoError(tb, err)

	for range 10 {
		m := createTestMessage()

		var res *dns.Msg
		res, err = client.ExchangeConnContext(ctx, conn, m, ri)
		require.NoError(tb, err)
		assertTestMessageResponse(tb, res)
	}
}

func BenchmarkServeUDP(b *testing.B) {
	benchmarkServe(b, dnscrypt.ProtoUDP)

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/dnscrypt
	//	cpu: Apple M4 Pro
	//	BenchmarkServeUDP-14    	    9199	    128165 ns/op	    5993 B/op	      60 allocs/op
	//	PASS
	//	ok  	github.com/AdguardTeam/dnscrypt	2.052s
}

func BenchmarkServeTCP(b *testing.B) {
	benchmarkServe(b, dnscrypt.ProtoTCP)

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/dnscrypt
	//	cpu: Apple M4 Pro
	//	BenchmarkServeTCP-14    	    9548	    120629 ns/op	    4864 B/op	      63 allocs/op
}

// benchmarkServe is a helper that benches [testServer] with given protocol.
//
// TODO(f.setrakov): Investigate the allocations increase.
func benchmarkServe(b *testing.B, proto dnscrypt.Proto) {
	srv, resolverPk, _ := newTestServer(b, &testHandler{}, proto)
	client := newTestClient(&dnscrypt.ClientConfig{Proto: proto})
	stamp := newTestServerStamp(srv, resolverPk)

	ctx := testutil.ContextWithTimeout(b, testTimeout)
	ri, err := client.DialStampContext(ctx, *stamp)
	require.NoError(b, err)
	require.NotNil(b, ri)

	conn, err := net.Dial(string(proto), stamp.ServerAddrStr)
	require.NoError(b, err)

	var resp *dns.Msg

	ctx = b.Context()

	b.ReportAllocs()
	for b.Loop() {
		m := createTestMessage()
		resp, err = client.ExchangeConnContext(ctx, conn, m, ri)
	}

	require.NoError(b, err)

	assertTestMessageResponse(b, resp)
}
