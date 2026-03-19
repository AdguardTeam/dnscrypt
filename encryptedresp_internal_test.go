package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/AdguardTeam/dnscrypt/internal/xsecretbox"
	"github.com/stretchr/testify/require"
)

func TestDNSCryptResponseEncryptDecryptXSalsa20Poly1305(t *testing.T) {
	t.Parallel()

	testDNSCryptResponseEncryptDecrypt(t, XSalsa20Poly1305)
}

func TestDNSCryptResponseEncryptDecryptXChacha20Poly1305(t *testing.T) {
	t.Parallel()

	testDNSCryptResponseEncryptDecrypt(t, XChacha20Poly1305)
}

// testDNSCryptResponseEncryptDecrypt is a helper that checks that the
// [EncryptedResponse] with the specified cryptographic construction correctly
// encrypts and decrypts data.
func testDNSCryptResponseEncryptDecrypt(tb testing.TB, esVersion CryptoConstruction) {
	tb.Helper()

	clientSecretKey, clientPublicKey := generateRandomKeyPair()
	serverSecretKey, serverPublicKey := generateRandomKeyPair()

	clientSharedKey, err := computeSharedKey(esVersion, &clientSecretKey, &serverPublicKey)
	require.NoError(tb, err)

	serverSharedKey, err := computeSharedKey(esVersion, &serverSecretKey, &clientPublicKey)
	require.NoError(tb, err)

	r1 := &EncryptedResponse{
		ESVersion: esVersion,
	}

	_, _ = rand.Read(r1.Nonce[:nonceSize/12])

	packet := make([]byte, 100)
	_, _ = rand.Read(packet[:])

	encrypted, err := r1.Encrypt(packet, serverSharedKey)
	require.NoError(tb, err)

	r2 := &EncryptedResponse{
		ESVersion: esVersion,
	}

	decrypted, err := r2.Decrypt(encrypted, clientSharedKey)
	require.NoError(tb, err)

	require.True(tb, bytes.Equal(packet, decrypted))

	_, err = r2.Decrypt(packet, clientSharedKey)
	require.NotNil(tb, err)

	_, err = r2.Decrypt([]byte{}, clientSharedKey)
	require.NotNil(tb, err)

	b := make([]byte, len(resolverMagic)+nonceSize+xsecretbox.TagSize+minDNSPacketSize)
	_, _ = rand.Read(b)
	_, err = r2.Decrypt(b, clientSharedKey)
	require.NotNil(tb, err)
}
