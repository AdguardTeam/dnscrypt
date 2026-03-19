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

	srv, _ := newTestServer(t, &testHandler{})
	stampBadProto := newTestServerStamp(srv, dnscrypt.ProtoUDP)
	stampBadProto.Proto = dnsstamps.StampProtoTypeDoH

	testCases := []struct {
		name       string
		proto      dnscrypt.Proto
		stampStr   string
		wantErrMsg string
	}{{
		name:       "invalid_stamp",
		proto:      dnscrypt.ProtoUDP,
		stampStr:   "invalid_stamp_str",
		wantErrMsg: "creating server stamp: stamps are expected to start with sdns://",
	}, {
		name:       "invalid_stamp_proto",
		stampStr:   stampBadProto.String(),
		wantErrMsg: dnscrypt.ErrInvalidDNSStamp.Error(),
	}, {
		name:     "tcp",
		proto:    dnscrypt.ProtoTCP,
		stampStr: newTestServerStamp(srv, dnscrypt.ProtoTCP).String(),
	}, {
		name:     "udp",
		proto:    dnscrypt.ProtoUDP,
		stampStr: newTestServerStamp(srv, dnscrypt.ProtoUDP).String(),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client := newTestClient(&dnscrypt.ClientConfig{Proto: tc.proto})
			ctx := testutil.ContextWithTimeout(t, testTimeout)
			info, err := client.DialContext(ctx, tc.stampStr)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			if tc.wantErrMsg == "" {
				require.NotNil(t, info)

				assert.True(t, info.ResolverCert.VerifySignature(srv.resolverPk))
				assert.Equal(t, prefixedHostname, info.ProviderName)
			}
		})
	}
}

func TestClient_ExchangeContext(t *testing.T) {
	t.Parallel()

	srv, _ := newTestServer(t, &testHandler{})

	require.True(t, t.Run("tcp", func(t *testing.T) {
		t.Parallel()

		stamp := newTestServerStamp(srv, dnscrypt.ProtoTCP)

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

		stamp := newTestServerStamp(srv, dnscrypt.ProtoUDP)

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
