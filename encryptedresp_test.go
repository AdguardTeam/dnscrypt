package dnscrypt

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/AdguardTeam/dnscrypt/xsecretbox"
	"github.com/stretchr/testify/require"
)

func TestDNSCryptResponseEncryptDecryptXSalsa20Poly1305(t *testing.T) {
	testDNSCryptResponseEncryptDecrypt(t, XSalsa20Poly1305)
}

func TestDNSCryptResponseEncryptDecryptXChacha20Poly1305(t *testing.T) {
	testDNSCryptResponseEncryptDecrypt(t, XChacha20Poly1305)
}

func testDNSCryptResponseEncryptDecrypt(t *testing.T, esVersion CryptoConstruction) {
	clientSecretKey, clientPublicKey := generateRandomKeyPair()
	serverSecretKey, serverPublicKey := generateRandomKeyPair()

	clientSharedKey, err := computeSharedKey(esVersion, &clientSecretKey, &serverPublicKey)
	require.NoError(t, err)

	serverSharedKey, err := computeSharedKey(esVersion, &serverSecretKey, &clientPublicKey)
	require.NoError(t, err)

	r1 := &EncryptedResponse{
		EsVersion: esVersion,
	}

	_, _ = rand.Read(r1.Nonce[:nonceSize/12])

	packet := make([]byte, 100)
	_, _ = rand.Read(packet[:])

	encrypted, err := r1.Encrypt(packet, serverSharedKey)
	require.NoError(t, err)

	r2 := &EncryptedResponse{
		EsVersion: esVersion,
	}

	decrypted, err := r2.Decrypt(encrypted, clientSharedKey)
	require.NoError(t, err)

	require.True(t, bytes.Equal(packet, decrypted))

	_, err = r2.Decrypt(packet, clientSharedKey)
	require.NotNil(t, err)

	_, err = r2.Decrypt([]byte{}, clientSharedKey)
	require.NotNil(t, err)

	b := make([]byte, len(resolverMagic)+nonceSize+xsecretbox.TagSize+minDNSPacketSize)
	_, _ = rand.Read(b)
	_, err = r2.Decrypt(b, clientSharedKey)
	require.NotNil(t, err)
}
