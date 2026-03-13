package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDNSCryptQueryEncryptDecryptXSalsa20Poly1305(t *testing.T) {
	testDNSCryptQueryEncryptDecrypt(t, XSalsa20Poly1305)
}

func TestDNSCryptQueryEncryptDecryptXChacha20Poly1305(t *testing.T) {
	testDNSCryptQueryEncryptDecrypt(t, XChacha20Poly1305)
}

func testDNSCryptQueryEncryptDecrypt(t *testing.T, esVersion CryptoConstruction) {
	clientSecretKey, clientPublicKey := generateRandomKeyPair()
	serverSecretKey, serverPublicKey := generateRandomKeyPair()

	clientSharedKey, err := computeSharedKey(esVersion, &clientSecretKey, &serverPublicKey)
	require.NoError(t, err)

	clientMagic := [clientMagicSize]byte{}
	_, _ = rand.Read(clientMagic[:])

	q1 := EncryptedQuery{
		EsVersion:   esVersion,
		ClientPk:    clientPublicKey,
		ClientMagic: clientMagic,
	}

	packet := make([]byte, 100)
	_, _ = rand.Read(packet[:])

	encrypted, err := q1.Encrypt(packet, clientSharedKey)
	require.NoError(t, err)

	q2 := EncryptedQuery{
		EsVersion:   esVersion,
		ClientMagic: clientMagic,
	}

	decrypted, err := q2.Decrypt(encrypted, serverSecretKey)
	require.NoError(t, err)

	// Check that packet is the same.
	require.True(t, bytes.Equal(packet, decrypted))
}
