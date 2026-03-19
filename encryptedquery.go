package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/AdguardTeam/dnscrypt/xsecretbox"
	"golang.org/x/crypto/nacl/secretbox"
)

// EncryptedQuery is a structure for encrypting and decrypting client queries.
//
// NOTE: Client Queries are using the following schema:
// <dnscrypt-query> ::= <client-magic> <client-pk> <client-nonce> <encrypted-query>
// <encrypted-query> ::= AE(<shared-key> <client-nonce> <client-nonce-pad>, <client-query> <client-query-pad>)
type EncryptedQuery struct {
	// EsVersion contains used encryption.
	EsVersion CryptoConstruction

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

// Encrypt encrypts the specified DNS query, returns encrypted data ready to be
// sent.  q.EsVersion, q.ClientMagic and q.ClientPk must be set.
//
// TODO(f.setrakov): Improve error handling.
func (q *EncryptedQuery) Encrypt(
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
	switch q.EsVersion {
	case XChacha20Poly1305:
		query = xsecretbox.Seal(query, nonce[:], padded, sharedKey[:])
	case XSalsa20Poly1305:
		var xsalsaNonce [nonceSize]byte
		copy(xsalsaNonce[:], nonce[:])
		query = secretbox.Seal(query, padded, &xsalsaNonce, &sharedKey)
	default:
		return nil, ErrEsVersion
	}

	return query, nil
}

// Decrypt decrypts the client query, returns decrypted DNS packet.
// q.ClientMagic and q.EsVersion must be set.
func (q *EncryptedQuery) Decrypt(
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

	sharedKey, err := computeSharedKey(q.EsVersion, &serverSecretKey, &q.ClientPk)
	if err != nil {
		return nil, err
	}

	idx = idx + KeySize
	copy(q.Nonce[:nonceSize/2], query[idx:idx+nonceSize/2])

	idx = idx + nonceSize/2
	encryptedQuery := query[idx:]

	switch q.EsVersion {
	case XChacha20Poly1305:
		packet, err = xsecretbox.Open(nil, q.Nonce[:], encryptedQuery, sharedKey[:])
		if err != nil {
			return nil, ErrInvalidQuery
		}
	case XSalsa20Poly1305:
		var xsalsaServerNonce [24]byte
		copy(xsalsaServerNonce[:], q.Nonce[:])
		var ok bool
		packet, ok = secretbox.Open(nil, encryptedQuery, &xsalsaServerNonce, &sharedKey)
		if !ok {
			return nil, ErrInvalidQuery
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
