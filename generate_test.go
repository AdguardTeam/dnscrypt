package dnscrypt_test

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/stretchr/testify/require"
)

func TestHexEncodeKey(t *testing.T) {
	t.Parallel()

	str := dnscrypt.HexEncodeKey([]byte{1, 2, 3, 4})
	require.Equal(t, "01020304", str)
}

func TestHexDecodeKey(t *testing.T) {
	t.Parallel()

	b, err := dnscrypt.HexDecodeKey("01:02:03:04")
	require.NoError(t, err)
	require.True(t, bytes.Equal(b, []byte{1, 2, 3, 4}))
}

func TestGenerateResolverConfig(t *testing.T) {
	t.Parallel()

	rc, err := dnscrypt.GenerateResolverConfig(testHostname, nil)
	require.NoError(t, err)
	require.Equal(t, dnscrypt.DNSCryptV2Prefix+testHostname, rc.ProviderName)
	require.Equal(t, ed25519.PrivateKeySize*2, len(rc.PrivateKey))
	require.Equal(t, dnscrypt.KeySize*2, len(rc.ResolverSk))
	require.Equal(t, dnscrypt.KeySize*2, len(rc.ResolverPk))

	cert, err := rc.CreateCert()
	require.NoError(t, err)
	require.True(t, cert.VerifyDate())

	publicKey, err := dnscrypt.HexDecodeKey(rc.PublicKey)
	require.NoError(t, err)
	require.True(t, cert.VerifySignature(publicKey))
}
