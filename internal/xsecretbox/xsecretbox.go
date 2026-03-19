// Package xsecretbox implements encryption/decryption of a message using
// specified keys.
package xsecretbox

import (
	"crypto/subtle"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305"
)

const (
	// KeySize is the size of the encryption key in bytes.
	KeySize = chacha20.KeySize

	// NonceSize is the size of the nonce in bytes.
	NonceSize = chacha20.NonceSizeX

	// TagSize is the size of the authentication tag in bytes.
	TagSize = poly1305.TagSize

	// BlockSize is the size of the cipher block in bytes.
	BlockSize = 64
)

// Seal encrypts and authenticates message using XChaCha20-Poly1305 and appends
// the result to out.  nonce must be [NonceSize] long.  key must be [KeySize]
// long.
func Seal(out, nonce, message, key []byte) (res []byte) {
	if len(nonce) != NonceSize {
		panic("unsupported nonce size")
	}

	if len(key) != KeySize {
		panic("unsupported key size")
	}

	var firstBlock [BlockSize]byte
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}

	cipher.XORKeyStream(firstBlock[:], firstBlock[:])
	var polyKey [KeySize]byte
	copy(polyKey[:], firstBlock[:KeySize])

	res, out = sliceForAppend(out, TagSize+len(message))
	firstMessageBlock := message
	if len(firstMessageBlock) > (BlockSize - KeySize) {
		firstMessageBlock = firstMessageBlock[:(BlockSize - KeySize)]
	}

	tagOut := out
	out = out[poly1305.TagSize:]
	for i, x := range firstMessageBlock {
		out[i] = firstBlock[(BlockSize-KeySize)+i] ^ x
	}

	message = message[len(firstMessageBlock):]
	ciphertext := out
	out = out[len(firstMessageBlock):]

	cipher.SetCounter(1)
	cipher.XORKeyStream(out, message)

	var tag [TagSize]byte
	hash := poly1305.New(&polyKey)
	_, _ = hash.Write(ciphertext)
	hash.Sum(tag[:0])
	copy(tagOut, tag[:])

	return res
}

// Open decrypts and authenticates the box using the XChaCha20-Poly1305
// algorithm, appending the result to the out parameter.  nonce must be
// [NonceSize] elements long.  key must be [KeySize] elements long.
func Open(out, nonce, box, key []byte) (res []byte, err error) {
	if len(nonce) != NonceSize {
		panic("unsupported nonce size")
	}

	if len(key) != KeySize {
		panic("unsupported key size")
	}

	if len(box) < TagSize {
		return nil, errCipherTextTooShort
	}

	var firstBlock [BlockSize]byte
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}

	cipher.XORKeyStream(firstBlock[:], firstBlock[:])
	var polyKey [KeySize]byte
	copy(polyKey[:], firstBlock[:KeySize])

	var tag [TagSize]byte
	ciphertext := box[TagSize:]
	hash := poly1305.New(&polyKey)
	_, _ = hash.Write(ciphertext)
	hash.Sum(tag[:0])

	if subtle.ConstantTimeCompare(tag[:], box[:TagSize]) != 1 {
		return nil, errCipherTextAuthenticationFail
	}

	res, out = sliceForAppend(out, len(ciphertext))

	firstMessageBlock := ciphertext
	if len(firstMessageBlock) > (BlockSize - KeySize) {
		firstMessageBlock = firstMessageBlock[:(BlockSize - KeySize)]
	}

	for i, x := range firstMessageBlock {
		out[i] = firstBlock[(BlockSize-KeySize)+i] ^ x
	}

	ciphertext = ciphertext[len(firstMessageBlock):]
	out = out[len(firstMessageBlock):]

	cipher.SetCounter(1)
	cipher.XORKeyStream(out, ciphertext)

	return res, nil
}

// sliceForAppend extends the input slice by n bytes and returns the extended
// slice and a tail slice that points to the appended region.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}

	tail = head[len(in):]

	return head, tail
}
