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

// encryptedQuery is a structure for encrypting and decrypting client queries.
//
// NOTE: Client Queries are using the following schema:
// <dnscrypt-query> ::= <client-magic> <client-pk> <client-nonce> <encrypted-query>
// <encrypted-query> ::= AE(<shared-key> <client-nonce> <client-nonce-pad>, <client-query> <client-query-pad>)
type encryptedQuery struct {
	// ESVersion contains used encryption.
	ESVersion CryptoConstruction

	// ClientMagic is a 8 byte identifier for the resolver certificate chosen by
	// the client.
	ClientMagic [clientMagicSize]byte

	// ClientPk is the client's public key.
	ClientPk [KeySize]byte

	// With a 24 bytes nonce, a question sent by a DNSCrypt client must be
	// encrypted using the shared secret, and a nonce constructed as follows: 12
	// bytes chosen by the client followed by 12 zero bytes.  The client's half
	// of the nonce can include a timestamp in addition to a counter or to
	// random bytes, so that when a response is received, the client can use
	// this timestamp to immediately discard responses to queries that have been
	// sent too long ago, or dated in the future.
	Nonce [nonceSize]byte
}

// encrypt encrypts the specified DNS query, returns encrypted data ready to be
// sent.  q.ESVersion, q.ClientMagic and q.ClientPk must be set.
func (q *encryptedQuery) encrypt(
	packet []byte,
	sharedKey [SharedKeySize]byte,
) (query []byte, err error) {
	binary.BigEndian.PutUint64(q.Nonce[:8], uint64(time.Now().UnixNano()))
	_, _ = rand.Read(q.Nonce[8:12])

	query = append(query, q.ClientMagic[:]...)
	query = append(query, q.ClientPk[:]...)
	query = append(query, q.Nonce[:nonceSize/2]...)

	padded := pad(packet)

	nonce := q.Nonce
	switch q.ESVersion {
	case XChacha20Poly1305:
		query = xsecretbox.Seal(query, nonce[:], padded, sharedKey[:])
	case XSalsa20Poly1305:
		var xsalsaNonce [nonceSize]byte
		copy(xsalsaNonce[:], nonce[:])
		query = secretbox.Seal(query, padded, &xsalsaNonce, &sharedKey)
	default:
		return nil, ErrESVersion
	}

	return query, nil
}

// decrypt decrypts the client query, returns decrypted DNS packet.
// q.ClientMagic and q.ESVersion must be set.
func (q *encryptedQuery) decrypt(
	query []byte,
	serverSecretKey [KeySize]byte,
) (packet []byte, err error) {
	headerLength := clientMagicSize + KeySize + nonceSize/2
	if len(query) < headerLength+xsecretbox.TagSize+minDNSPacketSize {
		return nil, ErrInvalidQuery
	}

	clientMagic := [clientMagicSize]byte{}
	copy(clientMagic[:], query[:clientMagicSize])
	if !bytes.Equal(clientMagic[:], q.ClientMagic[:]) {
		return nil, ErrInvalidClientMagic
	}

	idx := clientMagicSize
	copy(q.ClientPk[:KeySize], query[idx:idx+KeySize])

	sharedKey, err := computeSharedKey(q.ESVersion, &serverSecretKey, &q.ClientPk)
	if err != nil {
		return nil, fmt.Errorf("computing shared key: %w", err)
	}

	idx = idx + KeySize
	copy(q.Nonce[:nonceSize/2], query[idx:idx+nonceSize/2])

	idx = idx + nonceSize/2
	encryptedQuery := query[idx:]

	packet, err = q.decryptES(encryptedQuery, sharedKey)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	packet, err = unpad(packet)
	if err != nil {
		return nil, fmt.Errorf("remove packet padding: %w", err)
	}

	return packet, nil
}

// decryptES decrypts the query using the configured encryption method and the
// given shared key.
func (q *encryptedQuery) decryptES(
	query []byte,
	sharedKey [xsecretbox.KeySize]byte,
) (packet []byte, err error) {
	switch q.ESVersion {
	case XChacha20Poly1305:
		packet, err = xsecretbox.Open(nil, q.Nonce[:], query, sharedKey[:])
		if err != nil {
			return nil, fmt.Errorf("decrypting query: %s: %w", q.ESVersion, err)
		}
	case XSalsa20Poly1305:
		var xsalsaServerNonce [24]byte
		copy(xsalsaServerNonce[:], q.Nonce[:])
		var ok bool
		packet, ok = secretbox.Open(nil, query, &xsalsaServerNonce, &sharedKey)
		if !ok {
			return nil, fmt.Errorf("decrypting query: %s: %w", q.ESVersion, err)
		}
	default:
		return nil, ErrESVersion
	}

	return packet, nil
}
