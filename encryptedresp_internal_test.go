package dnscrypt

import (
	"crypto/rand"
	"testing"

	"github.com/AdguardTeam/dnscrypt/internal/xsecretbox"
	"github.com/stretchr/testify/assert"
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
// [encryptedResponse] with the specified cryptographic construction correctly
// encrypts and decrypts data.
func testDNSCryptResponseEncryptDecrypt(tb testing.TB, esVersion CryptoConstruction) {
	tb.Helper()

	clientSecretKey, clientPublicKey := generateRandomKeyPair()
	serverSecretKey, serverPublicKey := generateRandomKeyPair()

	clientSharedKey, err := computeSharedKey(esVersion, &clientSecretKey, &serverPublicKey)
	require.NoError(tb, err)

	serverSharedKey, err := computeSharedKey(esVersion, &serverSecretKey, &clientPublicKey)
	require.NoError(tb, err)

	r1 := &encryptedResponse{
		ESVersion: esVersion,
	}

	_, _ = rand.Read(r1.Nonce[:nonceSize/12])

	packet := make([]byte, 100)
	_, _ = rand.Read(packet[:])

	encrypted, err := r1.encrypt(packet, serverSharedKey)
	require.NoError(tb, err)

	r2 := &encryptedResponse{
		ESVersion: esVersion,
	}

	decrypted, err := r2.decrypt(encrypted, clientSharedKey)
	require.NoError(tb, err)

	assert.Equal(tb, packet, decrypted)

	_, err = r2.decrypt(packet, clientSharedKey)
	require.Error(tb, err)

	_, err = r2.decrypt([]byte{}, clientSharedKey)
	require.Error(tb, err)

	b := make([]byte, len(resolverMagic)+nonceSize+xsecretbox.TagSize+minDNSPacketSize)
	_, _ = rand.Read(b)
	_, err = r2.decrypt(b, clientSharedKey)
	require.Error(tb, err)
}
