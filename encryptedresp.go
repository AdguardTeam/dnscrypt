package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/AdguardTeam/dnscrypt/xsecretbox"
	"golang.org/x/crypto/nacl/secretbox"
)

// EncryptedResponse is used for encrypting/decrypting server responses.
//
// NOTE: Server responses are using the following schema:
// <dnscrypt-response> ::= <resolver-magic> <nonce> <encrypted-response>
// <encrypted-response> ::= AE(<shared-key>, <nonce>, <resolver-response> <resolver-response-pad>)
type EncryptedResponse struct {
	// EsVersion is the encryption to use.
	EsVersion CryptoConstruction

	// Nonce - <nonce> ::= <client-nonce> <resolver-nonce>
	// <client-nonce> ::= the nonce sent by the client in the related query.
	Nonce [nonceSize]byte
}

// Encrypt encrypts the server response.  r.EsVersion and r.Nonce must be set.
//
// TODO(f.setrakov): Improve error handling.
func (r *EncryptedResponse) Encrypt(
	packet []byte,
	sharedKey [SharedKeySize]byte,
) (response []byte, err error) {
	_, _ = rand.Read(r.Nonce[12:16])
	binary.BigEndian.PutUint64(r.Nonce[16:nonceSize], uint64(time.Now().UnixNano()))

	response = append(response, resolverMagic[:]...)
	response = append(response, r.Nonce[:]...)

	padded := pad(packet)

	nonce := r.Nonce
	switch r.EsVersion {
	case XChacha20Poly1305:
		response = xsecretbox.Seal(response, nonce[:], padded, sharedKey[:])
	case XSalsa20Poly1305:
		var xsalsaNonce [nonceSize]byte
		copy(xsalsaNonce[:], nonce[:])
		response = secretbox.Seal(response, padded, &xsalsaNonce, &sharedKey)
	default:
		return nil, ErrEsVersion
	}

	return response, nil
}

// Decrypt decrypts the server response.  r.EsVersion must be set.
func (r *EncryptedResponse) Decrypt(
	response []byte,
	sharedKey [SharedKeySize]byte,
) (packet []byte, err error) {
	headerLength := len(resolverMagic) + nonceSize
	if len(response) < headerLength+xsecretbox.TagSize+minDNSPacketSize {
		return nil, ErrInvalidResponse
	}

	magic := [resolverMagicSize]byte{}
	copy(magic[:], response[:resolverMagicSize])
	if !bytes.Equal(magic[:], resolverMagic[:]) {
		return nil, ErrInvalidResolverMagic
	}

	copy(r.Nonce[:], response[resolverMagicSize:nonceSize+resolverMagicSize])
	encryptedResponse := response[nonceSize+resolverMagicSize:]
	switch r.EsVersion {
	case XChacha20Poly1305:
		packet, err = xsecretbox.Open(nil, r.Nonce[:], encryptedResponse, sharedKey[:])
		if err != nil {
			return nil, ErrInvalidResponse
		}
	case XSalsa20Poly1305:
		var xsalsaServerNonce [24]byte
		copy(xsalsaServerNonce[:], r.Nonce[:])
		var ok bool
		packet, ok = secretbox.Open(nil, encryptedResponse, &xsalsaServerNonce, &sharedKey)
		if !ok {
			return nil, ErrInvalidResponse
		}
	default:
		return nil, ErrEsVersion
	}

	packet, err = unpad(packet)
	if err != nil {
		return nil, ErrInvalidPadding
	}

	return packet, nil
}
