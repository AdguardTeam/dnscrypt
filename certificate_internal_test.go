package dnscrypt

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCert_MarshalBinary(t *testing.T) {
	t.Parallel()

	cert, publicKey, _ := generateValidCert(t)
	assert.NotEqual(t, make([]byte, 64), cert.Signature[:])
	assert.True(t, cert.VerifySignature(publicKey))

	b, _ := cert.MarshalBinary()
	require.Len(t, b, certByteLength)

	cert2 := Certificate{}
	err := cert2.UnmarshalBinary(b)
	require.NoError(t, err)

	assert.Equal(t, cert.Serial, cert2.Serial)
	assert.Equal(t, cert.NotBefore, cert2.NotBefore)
	assert.Equal(t, cert.NotAfter, cert2.NotAfter)
	assert.Equal(t, cert.ESVersion, cert2.ESVersion)
	assert.Equal(t, cert.ClientMagic[:], cert2.ClientMagic[:])
	assert.Equal(t, cert.ResolverPk[:], cert2.ResolverPk[:])
	assert.Equal(t, cert.Signature[:], cert2.Signature[:])
}

func TestCert_UnmarshalBinary(t *testing.T) {
	t.Parallel()

	// dig -t txt 2.dnscrypt-cert.opendns.com. -p 443 @208.67.220.220.
	certBytes, err := os.ReadFile("testdata/dnscrypt-cert.opendns.txt")
	require.NoError(t, err)

	b := unpackTxtString(string(certBytes))
	require.NoError(t, err)

	cert := &Certificate{}
	err = cert.UnmarshalBinary(b)
	require.NoError(t, err)

	assert.Equal(t, uint32(1574811744), cert.Serial)
	assert.Equal(t, XSalsa20Poly1305, cert.ESVersion)
	assert.Equal(t, uint32(1574811744), cert.NotBefore)
	assert.Equal(t, uint32(1606347744), cert.NotAfter)
}

// generateValidCert is a helper that generates a valid certificate and key pair
// using default parameters for testing purposes.
func generateValidCert(
	tb testing.TB,
) (cert *Certificate, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) {
	tb.Helper()

	cert = &Certificate{
		Serial:    1,
		NotAfter:  uint32(time.Now().Add(1 * time.Hour).Unix()),
		NotBefore: uint32(time.Now().Add(-1 * time.Hour).Unix()),
		ESVersion: XChacha20Poly1305,
	}

	resolverSk, resolverPk := generateRandomKeyPair()
	copy(cert.ResolverPk[:], resolverPk[:])
	copy(cert.ResolverSk[:], resolverSk[:])

	assert.Equal(tb, make([]byte, 64), cert.Signature[:])

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(tb, err)

	cert.Sign(privateKey)

	return cert, publicKey, privateKey
}
