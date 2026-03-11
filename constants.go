package dnscrypt

import "github.com/AdguardTeam/golibs/errors"

const (
	// ErrTooShort is returned when the DNS query is shorter than possible.
	ErrTooShort errors.Error = "message is too short"

	// ErrQueryTooLarge is returned when the DNS query is larger than max
	// allowed size.
	ErrQueryTooLarge errors.Error = "DNSCrypt query is too large"

	// ErrEsVersion is returned when the cert contains unsupported es-version.
	ErrEsVersion errors.Error = "unsupported es-version"

	// ErrInvalidDate is returned when the cert is not valid for the current
	// time.
	ErrInvalidDate errors.Error = "cert has invalid ts-start or ts-end"

	// ErrInvalidCertSignature is returned when the cert has invalid signature.
	ErrInvalidCertSignature errors.Error = "cert has invalid signature"

	// ErrInvalidQuery is returned when it failed to decrypt a DNSCrypt query.
	ErrInvalidQuery errors.Error = "DNSCrypt query is invalid and cannot be decrypted"

	// ErrInvalidClientMagic is returned when client-magic does not match.
	ErrInvalidClientMagic errors.Error = "DNSCrypt query contains invalid client magic"

	// ErrInvalidResolverMagic is returned when server-magic does not match.
	ErrInvalidResolverMagic errors.Error = "DNSCrypt response contains invalid resolver magic"

	// ErrInvalidResponse is returned when it failed to decrypt a DNSCrypt
	// response.
	ErrInvalidResponse errors.Error = "DNSCrypt response is invalid and cannot be decrypted"

	// ErrInvalidPadding is returned when it failed to unpad a query.
	ErrInvalidPadding errors.Error = "invalid padding"

	// ErrInvalidDNSStamp is returned when an invalid DNS stamp is provided.
	ErrInvalidDNSStamp errors.Error = "invalid DNS stamp"

	// ErrFailedToFetchCert is returned when it failed to fetch DNSCrypt
	// certificate.
	ErrFailedToFetchCert errors.Error = "failed to fetch DNSCrypt certificate"

	// ErrCertTooShort is returned when it failed to deserialize cert, too
	// short.
	ErrCertTooShort errors.Error = "cert is too short"

	// ErrCertMagic is returned when an invalid cert magic is encountered.
	ErrCertMagic errors.Error = "invalid cert magic"

	// ErrServerConfig is returned when it failed to start the DNSCrypt server
	// due to invalid configuration.
	ErrServerConfig errors.Error = "invalid server configuration"

	// ErrServerNotStarted is returned if there's nothing to shutdown.
	ErrServerNotStarted errors.Error = "server is not started"
)

const (
	// minUDPQuestionSize is a variable length, initially set to 256 bytes,
	// and must be a multiple of 64 bytes (see https://dnscrypt.info/protocol).
	// Some servers do not work if padded length is less than 256.  Example:
	// Quad9.
	minUDPQuestionSize = 256

	// minDNSPacketSize is the minimum possible DNS packet size.
	minDNSPacketSize = 12 + 5

	// keySize is the size of public and secret keys in bytes.  See 11.
	// Authenticated encryption and key exchange algorithm.  The public and
	// secret keys are 32 bytes long in storage.
	keySize = 32

	// sharedKeySize is the size of the shared key used to encrypt/decrypt
	// messages.
	sharedKeySize = 32

	// clientMagicSize is the size of ClientMagic in bytes.  ClientMagic is
	// the first 8 bytes of a client query that is to be built using the
	// information from this certificate.  It may be a truncated public key.
	// Two valid certificates cannot share the same <client-magic>.
	clientMagicSize = 8

	// nonceSize is the size of the nonce in bytes.  When using
	// X25519-XSalsa20Poly1305, this construction requires a 24 bytes nonce,
	// that must not be reused for a given shared secret.
	nonceSize = 24

	// resolverMagicSize is the size of resolver magic in bytes.  It is the
	// first 8 bytes of every dnscrypt response.  Must match resolverMagic.
	resolverMagicSize = 8
)

var (
	// certMagic is a bytes sequence that must be in the beginning of the
	// serialized cert.
	certMagic = [4]byte{0x44, 0x4e, 0x53, 0x43}

	// resolverMagic is a byte sequence that must be in the beginning of every
	// response.
	resolverMagic = []byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
)

// CryptoConstruction represents the encryption algorithm (either
// XSalsa20Poly1305 or XChacha20Poly1305).
type CryptoConstruction uint16

const (
	// UndefinedConstruction is the default value for empty CertInfo only.
	UndefinedConstruction CryptoConstruction = iota

	// XSalsa20Poly1305 represents XSalsa20Poly1305 encryption.
	XSalsa20Poly1305 CryptoConstruction = 0x0001

	// XChacha20Poly1305 represents XChacha20Poly1305 encryption.
	XChacha20Poly1305 CryptoConstruction = 0x0002
)

// String returns the string representation of CryptoConstruction.
func (c CryptoConstruction) String() (construction string) {
	switch c {
	case XChacha20Poly1305:
		return "XChacha20Poly1305"
	case XSalsa20Poly1305:
		return "XSalsa20Poly1305"
	default:
		return "Unknown"
	}
}

// Proto represents the base network protocol.
type Proto string

const (
	// ProtoUDP represents the UDP protocol.
	ProtoUDP Proto = "udp"

	// ProtoTCP represents the TCP protocol.
	ProtoTCP Proto = "tcp"
)
