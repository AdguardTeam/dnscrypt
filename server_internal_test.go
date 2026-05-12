package dnscrypt

import (
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLogger is a common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

func TestServer_ServeError(t *testing.T) {
	t.Parallel()

	rc, err := GenerateResolverConfig("example.org", nil, testTimeout)
	require.NoError(t, err)

	cert, err := rc.NewCert()
	require.NoError(t, err)

	dialer := net.Dialer{}

	// TODO(f.setrakov): Consider moving to golibs.
	addr := netip.AddrPortFrom(netutil.IPv4Localhost(), 0)

	require.True(t, t.Run("closed_udp_listener", func(t *testing.T) {
		var s *Server
		s, err = NewServer(&ServerConfig{
			Logger:       testLogger,
			ProviderName: rc.ProviderName,
			ResolverCert: cert,
			Proto:        ProtoUDP,
			Addr:         addr,
		})
		require.NoError(t, err)

		s.started = true

		addr := &net.UDPAddr{IP: net.IPv4zero}
		var udpConn *net.UDPConn
		udpConn, err = net.ListenUDP(string(ProtoUDP), addr)
		require.NoError(t, err)

		ctx := testutil.ContextWithTimeout(t, testTimeout)

		resCh := make(chan error, 1)
		s.udpConn = udpConn

		go func() {
			pt := testutil.NewPanicT(t)
			testutil.RequireSend(pt, resCh, s.serveUDP(ctx), testTimeout)
		}()

		var conn net.Conn
		conn, err = dialer.DialContext(ctx, string(ProtoUDP), udpConn.LocalAddr().String())
		require.NoError(t, err)
		require.NoError(t, conn.Close())
		require.NoError(t, udpConn.Close())

		var ok bool
		err, ok = testutil.RequireReceive(t, resCh, testTimeout)
		require.True(t, ok)

		assert.ErrorIs(t, err, net.ErrClosed)
	}))

	require.True(t, t.Run("closed_tcp_listener", func(t *testing.T) {
		var s *Server
		s, err = NewServer(&ServerConfig{
			Logger:       testLogger,
			ProviderName: rc.ProviderName,
			ResolverCert: cert,
			Proto:        ProtoTCP,
			Addr:         addr,
		})
		require.NoError(t, err)

		s.started = true

		addr := &net.TCPAddr{IP: net.IPv4zero}

		var tcpListen net.Listener
		tcpListen, err = net.ListenTCP(string(ProtoTCP), addr)
		require.NoError(t, err)

		ctx := testutil.ContextWithTimeout(t, testTimeout)

		resCh := make(chan error, 1)
		s.tcpListener = tcpListen

		go func() {
			pt := testutil.NewPanicT(t)
			testutil.RequireSend(pt, resCh, s.serveTCP(ctx), testTimeout)
		}()

		var conn net.Conn
		conn, err = dialer.DialContext(ctx, string(ProtoTCP), tcpListen.Addr().String())
		require.NoError(t, err)
		require.NoError(t, conn.Close())
		require.NoError(t, tcpListen.Close())

		var ok bool
		err, ok = testutil.RequireReceive(t, resCh, testTimeout)
		require.True(t, ok)

		assert.ErrorIs(t, err, net.ErrClosed)
	}))
}
