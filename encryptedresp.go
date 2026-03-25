package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/AdguardTeam/dnscrypt/internal/xsecretbox"
	"golang.org/x/crypto/nacl/secretbox"
)

// encryptedResponse is used for encrypting/decrypting server responses.
//
// NOTE: Server responses are using the following schema:
// <dnscrypt-response> ::= <resolver-magic> <nonce> <encrypted-response>
// <encrypted-response> ::= AE(<shared-key>, <nonce>, <resolver-response> <resolver-response-pad>)
type encryptedResponse struct {
	// ESVersion is the encryption to use.
	ESVersion CryptoConstruction

	// Nonce - <nonce> ::= <client-nonce> <resolver-nonce>
	// <client-nonce> ::= the nonce sent by the client in the related query.
	Nonce [nonceSize]byte
}

// encrypt encrypts the server response.  r.ESVersion and r.Nonce must be set.
func (r *encryptedResponse) encrypt(
	packet []byte,
	sharedKey [SharedKeySize]byte,
) (response []byte, err error) {
	_, _ = rand.Read(r.Nonce[12:16])
	binary.BigEndian.PutUint64(r.Nonce[16:nonceSize], uint64(time.Now().UnixNano()))

	response = append(response, resolverMagic[:]...)
	response = append(response, r.Nonce[:]...)

	padded := pad(packet)

	nonce := r.Nonce
	switch r.ESVersion {
	case XChacha20Poly1305:
		response = xsecretbox.Seal(response, nonce[:], padded, sharedKey[:])
	case XSalsa20Poly1305:
		var xsalsaNonce [nonceSize]byte
		copy(xsalsaNonce[:], nonce[:])
		response = secretbox.Seal(response, padded, &xsalsaNonce, &sharedKey)
	default:
		return nil, ErrESVersion
	}

	return response, nil
}

// decrypt decrypts the server response.  r.ESVersion must be set.
func (r *encryptedResponse) decrypt(
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
	switch r.ESVersion {
	case XChacha20Poly1305:
		packet, err = xsecretbox.Open(nil, r.Nonce[:], encryptedResponse, sharedKey[:])
		if err != nil {
			return nil, fmt.Errorf("decrypting response: %s: %w", r.ESVersion, err)
		}
	case XSalsa20Poly1305:
		var xsalsaServerNonce [24]byte
		copy(xsalsaServerNonce[:], r.Nonce[:])
		var ok bool
		packet, ok = secretbox.Open(nil, encryptedResponse, &xsalsaServerNonce, &sharedKey)
		if !ok {
			return nil, fmt.Errorf("decrypting response: %s: %w", r.ESVersion, err)
		}
	default:
		return nil, ErrESVersion
	}

	packet, err = unpad(packet)
	if err != nil {
		return nil, fmt.Errorf("removing packet padding: %w", err)
	}

	return packet, nil
}
