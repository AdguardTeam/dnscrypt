package dnscrypt

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDNSCryptQueryEncryptDecryptXSalsa20Poly1305(t *testing.T) {
	t.Parallel()

	testDNSCryptQueryEncryptDecrypt(t, XSalsa20Poly1305)
}

func TestDNSCryptQueryEncryptDecryptXChacha20Poly1305(t *testing.T) {
	t.Parallel()

	testDNSCryptQueryEncryptDecrypt(t, XChacha20Poly1305)
}

// testDNSCryptQueryEncryptDecrypt is a helper that checks that the
// [encryptedQuery] with the specified cryptographic construction correctly
// encrypts and decrypts data.
func testDNSCryptQueryEncryptDecrypt(tb testing.TB, esVersion CryptoConstruction) {
	tb.Helper()

	clientSecretKey, clientPublicKey := generateRandomKeyPair()
	serverSecretKey, serverPublicKey := generateRandomKeyPair()

	clientSharedKey, err := computeSharedKey(esVersion, &clientSecretKey, &serverPublicKey)
	require.NoError(tb, err)

	clientMagic := [clientMagicSize]byte{}
	_, _ = rand.Read(clientMagic[:])

	q1 := &encryptedQuery{
		ESVersion:   esVersion,
		ClientPk:    clientPublicKey,
		ClientMagic: clientMagic,
	}

	packet := make([]byte, 100)
	_, _ = rand.Read(packet[:])

	encrypted, err := q1.encrypt(packet, clientSharedKey)
	require.NoError(tb, err)

	q2 := &encryptedQuery{
		ESVersion:   esVersion,
		ClientMagic: clientMagic,
	}

	decrypted, err := q2.decrypt(encrypted, serverSecretKey)
	require.NoError(tb, err)

	require.Equal(tb, packet, decrypted)
}
