// Package dnscrypt includes client-side and server-side implementations of the
// DNSCrypt v2.  See https://dnscrypt.info/protocol for a detailed description
// of the protocol.
package dnscrypt

import (
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
)

const (
	// minUDPQuestionSize is a variable length, initially set to 256 bytes,
	// and must be a multiple of 64 bytes (see https://dnscrypt.info/protocol).
	// Some servers do not work if padded length is less than 256.  Example:
	// Quad9.
	minUDPQuestionSize = 256

	// minDNSPacketSize is the minimum possible DNS packet size.
	minDNSPacketSize = 12 + 5

	// KeySize is the size of public and secret keys in bytes.  See
	// https://dnscrypt.info/protocol for more information.
	KeySize = 32

	// sharedKeySize is the size of the shared key used to encrypt/decrypt
	// messages.
	SharedKeySize = 32

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

// Proto represents the base network protocol.
type Proto string

const (
	// ProtoUDP represents the UDP protocol.
	ProtoUDP Proto = "udp"

	// ProtoTCP represents the TCP protocol.
	ProtoTCP Proto = "tcp"
)

// ProtoFromString converts s into a Proto and makes sure it is valid.  This
// should be preferred to a simple type conversion.
func ProtoFromString(s string) (p Proto, err error) {
	switch p = Proto(s); p {
	case ProtoUDP:
		return ProtoUDP, nil
	case ProtoTCP:
		return ProtoTCP, nil
	default:
		return "", fmt.Errorf(
			"proto: %w: %q, supported: %q",
			errors.ErrBadEnumValue,
			s,
			[]string{string(ProtoUDP), string(ProtoTCP)},
		)
	}
}
