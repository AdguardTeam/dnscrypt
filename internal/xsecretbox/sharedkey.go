package xsecretbox

import (
	"fmt"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/curve25519"
)

// SharedKey computes a shared secret compatible with the one used by
// 'crypto_box_xchacha20poly1305'.
//
// TODO(f.setarakov): Find out what is 'crypto_box_xchacha20poly1305'.
func SharedKey(
	secretKey [curve25519.ScalarSize]byte,
	publicKey [curve25519.PointSize]byte,
) (sharedKey [KeySize]byte, err error) {
	sk, err := curve25519.X25519(secretKey[:], publicKey[:])
	if err != nil {
		return sharedKey, fmt.Errorf("computing x25519: %w", err)
	}

	c := byte(0)
	for i := 0; i < KeySize; i++ {
		sharedKey[i] = sk[i]
		c |= sk[i]
	}

	if c == 0 {
		return sharedKey, errWeakPublicKey
	}

	var nonce [16]byte
	hRes, err := chacha20.HChaCha20(sharedKey[:], nonce[:])
	if err != nil {
		return [KeySize]byte{}, fmt.Errorf("computing hchacha20: %w", err)
	}

	return ([KeySize]byte)(hRes), nil
}
