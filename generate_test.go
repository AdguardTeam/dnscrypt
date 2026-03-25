package dnscrypt_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/ameshkov/dnsstamps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHexEncodeKey(t *testing.T) {
	t.Parallel()

	str := dnscrypt.HexEncodeKey([]byte{1, 2, 3, 4})
	assert.Equal(t, "01020304", str)
}

func TestHexDecodeKey(t *testing.T) {
	t.Parallel()

	b, err := dnscrypt.HexDecodeKey("01:02:03:04")
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 2, 3, 4}, b)
}

func TestGenerateResolverConfig(t *testing.T) {
	t.Parallel()

	rc, err := dnscrypt.GenerateResolverConfig(testHostname, nil)
	require.NoError(t, err)
	assert.Equal(t, dnscrypt.DNSCryptV2Prefix+testHostname, rc.ProviderName)
	assert.Len(t, rc.ResolverSk, dnscrypt.KeySize*2)
	assert.Len(t, rc.PrivateKey, ed25519.PrivateKeySize*2)
	assert.Len(t, rc.ResolverPk, dnscrypt.KeySize*2)

	cert, err := rc.NewCert()
	require.NoError(t, err)
	assert.True(t, cert.VerifyDate())

	publicKey, err := dnscrypt.HexDecodeKey(rc.PublicKey)
	require.NoError(t, err)
	assert.True(t, cert.VerifySignature(publicKey))
}

func TestResolverConfig_CreateStamp(t *testing.T) {
	t.Parallel()

	rc, err := dnscrypt.GenerateResolverConfig(testHostname, nil)
	require.NoError(t, err)

	wantPk, err := dnscrypt.HexDecodeKey(rc.PublicKey)
	require.NoError(t, err)

	stamp, err := rc.CreateStamp(testHostname)
	require.NoError(t, err)

	assert.Equal(t, prefixedHostname, stamp.ProviderName)
	assert.Equal(t, wantPk, stamp.ServerPk)
	assert.Equal(t, testHostname, stamp.ServerAddrStr)
	assert.Equal(t, dnsstamps.StampProtoTypeDNSCrypt, stamp.Proto)
}
