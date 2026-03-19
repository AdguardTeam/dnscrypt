package dnscrypt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCert_MarshalBinary(t *testing.T) {
	t.Parallel()

	cert, publicKey, _ := generateValidCert(t)
	require.False(t, bytes.Equal(cert.Signature[:], make([]byte, 64)))
	require.True(t, cert.VerifySignature(publicKey))

	b, _ := cert.MarshalBinary()
	require.Equal(t, certByteLength, len(b))

	cert2 := Cert{}
	err := cert2.UnmarshalBinary(b)
	require.NoError(t, err)
	require.Equal(t, cert.Serial, cert2.Serial)
	require.Equal(t, cert.NotBefore, cert2.NotBefore)
	require.Equal(t, cert.NotAfter, cert2.NotAfter)
	require.Equal(t, cert.ESVersion, cert2.ESVersion)
	require.True(t, bytes.Equal(cert.ClientMagic[:], cert2.ClientMagic[:]))
	require.True(t, bytes.Equal(cert.ResolverPk[:], cert2.ResolverPk[:]))
	require.True(t, bytes.Equal(cert.Signature[:], cert2.Signature[:]))
}

func TestCert_UnmarshalBinary(t *testing.T) {
	t.Parallel()

	// dig -t txt 2.dnscrypt-cert.opendns.com. -p 443 @208.67.220.220.
	certBytes, err := os.ReadFile("testdata/dnscrypt-cert.opendns.txt")
	require.NoError(t, err)

	b := unpackTxtString(string(certBytes))
	require.NoError(t, err)

	cert := &Cert{}
	err = cert.UnmarshalBinary(b)
	require.NoError(t, err)
	require.Equal(t, uint32(1574811744), cert.Serial)
	require.Equal(t, XSalsa20Poly1305, cert.ESVersion)
	require.Equal(t, uint32(1574811744), cert.NotBefore)
	require.Equal(t, uint32(1606347744), cert.NotAfter)
}

// generateValidCert is a helper that generates a valid certificate and key pair
// using default parameters for testing purposes.
func generateValidCert(
	tb testing.TB,
) (cert *Cert, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) {
	tb.Helper()

	cert = &Cert{
		Serial:    1,
		NotAfter:  uint32(time.Now().Add(1 * time.Hour).Unix()),
		NotBefore: uint32(time.Now().Add(-1 * time.Hour).Unix()),
		ESVersion: XChacha20Poly1305,
	}

	resolverSk, resolverPk := generateRandomKeyPair()
	copy(cert.ResolverPk[:], resolverPk[:])
	copy(cert.ResolverSk[:], resolverSk[:])

	require.True(tb, bytes.Equal(cert.Signature[:], make([]byte, 64)))

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(tb, err)

	cert.Sign(privateKey)

	return cert, publicKey, privateKey
}
