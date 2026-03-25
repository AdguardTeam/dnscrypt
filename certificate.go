package dnscrypt

import (
	"bytes"
	"crypto/ed25519"
	"encoding"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/validate"
)

// certByteLength is the standard length of a certificate's byte representation.
const certByteLength = 124

// Certificate is a DNSCrypt server certificate.  See [ResolverConfig] for more
// info on how to create one.
type Certificate struct {
	// Serial is a 4 byte serial number in big-endian format.  If more than
	// one certificates are valid, the client must prefer the certificate with
	// a higher serial number.
	Serial uint32

	// ESVersion is the cryptographic construction to use with this
	// certificate.
	ESVersion CryptoConstruction

	// Signature is a 64-byte signature of (<resolver-pk> <client-magic>
	// <serial> <ts-start> <ts-end> <extensions>) using the Ed25519 algorithm
	// and the provider secret key.  Ed25519 must be used in this version of
	// the protocol.
	Signature [ed25519.SignatureSize]byte

	// ResolverPk is the resolver's short-term public key, which is 32 bytes
	// when using X25519.  This key is used to encrypt/decrypt DNS queries.
	ResolverPk [KeySize]byte

	// ResolverSk is the resolver's short-term private key, which is 32 bytes
	// when using X25519.  Note that it's only used in the server implementation
	// and never serialized/deserialized.  This key is used to encrypt/decrypt
	// DNS queries.
	ResolverSk [KeySize]byte

	// ClientMagic is the first 8 bytes of a client query that is to be built
	// using the information from this certificate.  It may be a truncated
	// public key.  Two valid certificates cannot share the same <client-magic>.
	ClientMagic [clientMagicSize]byte

	// NotBefore is the date the certificate is valid from, as a big-endian
	// 4-byte unsigned Unix timestamp.
	NotBefore uint32

	// NotAfter is the date the certificate is valid until (inclusive), as a
	// big-endian 4-byte unsigned Unix timestamp.
	NotAfter uint32
}

// type check
var _ encoding.BinaryMarshaler = (*Certificate)(nil)

// MarshalBinary implements the [encoding.BinaryMarshaler] interface for
// *Certificate.  The certificate is serialised into a byte slice using the
// following schema:
// <cert> ::= <cert-magic> <es-version> <protocol-minor-version> <signature>
// <resolver-pk> <client-magic> <serial> <ts-start> <ts-end>
//
// Certificates made of these information, without extensions, are 116 bytes
// long.  With the addition of the cert-magic, es-version and
// protocol-minor-version, the record is [certByteLength] bytes long.  err is
// always nil.
func (c *Certificate) MarshalBinary() (serialized []byte, err error) {
	serialized = make([]byte, certByteLength)
	copy(serialized[:4], certMagic[:])
	binary.BigEndian.PutUint16(serialized[4:6], uint16(c.ESVersion))
	copy(serialized[6:8], []byte{0, 0})
	copy(serialized[8:72], c.Signature[:ed25519.SignatureSize])
	c.writeSigned(serialized[72:])

	return serialized, nil
}

// type check
var _ validate.Interface = (*Certificate)(nil)

// Validate implements the [validate.Interface] for *Certificate.
func (c *Certificate) Validate() (err error) {
	if c.ESVersion == UndefinedConstruction {
		return ErrESVersion
	}

	if !c.VerifyDate() {
		return ErrInvalidDate
	}

	return nil
}

// type check
var _ encoding.BinaryUnmarshaler = (*Certificate)(nil)

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface for
// *Certificate.  Certificate is being deserialized using the following schema:
// <cert> ::= <cert-magic> <es-version> <protocol-minor-version> <signature>
// <resolver-pk> <client-magic> <serial> <ts-start> <ts-end>
func (c *Certificate) UnmarshalBinary(b []byte) (err error) {
	if len(b) < certByteLength {
		return ErrCertTooShort
	}

	if !bytes.Equal(b[:4], certMagic[:4]) {
		return ErrCertMagic
	}

	switch esVersion := binary.BigEndian.Uint16(b[4:6]); esVersion {
	case uint16(XSalsa20Poly1305):
		c.ESVersion = XSalsa20Poly1305
	case uint16(XChacha20Poly1305):
		c.ESVersion = XChacha20Poly1305
	default:
		return ErrESVersion
	}

	copy(c.Signature[:], b[8:72])
	copy(c.ResolverPk[:], b[72:104])
	copy(c.ClientMagic[:], b[104:112])

	c.Serial = binary.BigEndian.Uint32(b[112:116])
	c.NotBefore = binary.BigEndian.Uint32(b[116:120])
	c.NotAfter = binary.BigEndian.Uint32(b[120:certByteLength])

	return nil
}

// VerifyDate checks that the cert is valid at this moment.
func (c *Certificate) VerifyDate() (ok bool) {
	if c.NotBefore >= c.NotAfter {
		return false
	}

	now := uint32(time.Now().Unix())
	if now > c.NotAfter || now < c.NotBefore {
		return false
	}

	return true
}

// VerifySignature checks if the cert is properly signed with the specified
// signature.  publicKey must not be nil.
func (c *Certificate) VerifySignature(publicKey ed25519.PublicKey) (ok bool) {
	b := make([]byte, 52)
	c.writeSigned(b)

	return ed25519.Verify(publicKey, b, c.Signature[:])
}

// Sign creates cert signature.  privateKey must not be nil.
func (c *Certificate) Sign(privateKey ed25519.PrivateKey) {
	b := make([]byte, 52)
	c.writeSigned(b)
	signature := ed25519.Sign(privateKey, b)
	copy(c.Signature[:64], signature[:64])
}

// type check
var _ fmt.Stringer = (*Certificate)(nil)

// String implements the [fmt.Stringer] interface for *Certificate.
func (c *Certificate) String() (s string) {
	return fmt.Sprintf(
		"Certificate Serial=%d NotBefore=%s NotAfter=%s ESVersion=%s",
		c.Serial,
		time.Unix(int64(c.NotBefore), 0),
		time.Unix(int64(c.NotAfter), 0),
		c.ESVersion,
	)
}

// writeSigned writes certificate to dst using the following schema:
// <resolver-pk> <client-magic> <serial> <ts-start> <ts-end>
func (c *Certificate) writeSigned(dst []byte) {
	copy(dst[:32], c.ResolverPk[:KeySize])
	copy(dst[32:40], c.ClientMagic[:clientMagicSize])
	binary.BigEndian.PutUint32(dst[40:44], c.Serial)
	binary.BigEndian.PutUint32(dst[44:48], c.NotBefore)
	binary.BigEndian.PutUint32(dst[48:52], c.NotAfter)
}
