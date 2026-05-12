package dnscrypt_test

import (
	"testing"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/ameshkov/dnsstamps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_DialContext(t *testing.T) {
	t.Parallel()

	require.True(t, t.Run("tcp", func(t *testing.T) {
		srv, resolverPk, _ := newTestServer(t, &testHandler{}, dnscrypt.ProtoTCP)
		stamp := newTestServerStamp(srv, resolverPk)
		client := newTestClient(&dnscrypt.ClientConfig{Proto: dnscrypt.ProtoTCP})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		info, err := client.DialContext(ctx, stamp.String())
		require.NoError(t, err)
		require.NotNil(t, info)

		assert.True(t, info.ResolverCert.VerifySignature(resolverPk))
		assert.Equal(t, prefixedHostname, info.ProviderName)
	}))

	require.True(t, t.Run("udp", func(t *testing.T) {
		srv, resolverPk, _ := newTestServer(t, &testHandler{}, dnscrypt.ProtoUDP)
		stamp := newTestServerStamp(srv, resolverPk)
		client := newTestClient(&dnscrypt.ClientConfig{Proto: dnscrypt.ProtoUDP})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		info, err := client.DialContext(ctx, stamp.String())
		require.NoError(t, err)
		require.NotNil(t, info)

		assert.True(t, info.ResolverCert.VerifySignature(resolverPk))
		assert.Equal(t, prefixedHostname, info.ProviderName)
	}))

	require.True(t, t.Run("invalid_proto_stamp", func(t *testing.T) {
		srv, resolverPk, _ := newTestServer(t, &testHandler{}, dnscrypt.ProtoUDP)
		stamp := newTestServerStamp(srv, resolverPk)
		stamp.Proto = dnsstamps.StampProtoTypeDoH
		client := newTestClient(&dnscrypt.ClientConfig{Proto: dnscrypt.ProtoUDP})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		_, err := client.DialContext(ctx, stamp.String())
		testutil.AssertErrorMsg(t, dnscrypt.ErrInvalidDNSStamp.Error(), err)
	}))

	require.True(t, t.Run("invalid_stamp", func(t *testing.T) {
		client := newTestClient(&dnscrypt.ClientConfig{Proto: dnscrypt.ProtoUDP})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		_, err := client.DialContext(ctx, "invalid_stamp")
		testutil.AssertErrorMsg(
			t,
			`creating server stamp: stamps are expected to start with sdns://`,
			err,
		)
	}))
}

func TestClient_ExchangeContext(t *testing.T) {
	t.Parallel()

	require.True(t, t.Run("tcp", func(t *testing.T) {
		t.Parallel()

		srv, resolverPk, _ := newTestServer(t, &testHandler{}, dnscrypt.ProtoTCP)
		stamp := newTestServerStamp(srv, resolverPk)

		client := newTestClient(&dnscrypt.ClientConfig{Proto: dnscrypt.ProtoTCP})
		ctx := testutil.ContextWithTimeout(t, testTimeout)
		info, err := client.DialContext(ctx, stamp.String())
		require.NoError(t, err)

		req := createTestMessage()
		resp, err := client.ExchangeContext(ctx, req, info)
		require.NoError(t, err)

		assertTestMessageResponse(t, resp)
	}))

	require.True(t, t.Run("udp", func(t *testing.T) {
		t.Parallel()

		srv, resolverPk, _ := newTestServer(t, &testHandler{}, dnscrypt.ProtoUDP)
		stamp := newTestServerStamp(srv, resolverPk)

		client := newTestClient(&dnscrypt.ClientConfig{Proto: dnscrypt.ProtoUDP})
		ctx := testutil.ContextWithTimeout(t, testTimeout)
		info, err := client.DialContext(ctx, stamp.String())
		require.NoError(t, err)

		req := createTestMessage()
		resp, err := client.ExchangeContext(ctx, req, info)
		require.NoError(t, err)

		assertTestMessageResponse(t, resp)
	}))
}
