package dnscrypt

import (
	"github.com/AdguardTeam/dnscrypt/internal/xsecretbox"
	"golang.org/x/crypto/nacl/box"
)

// Prior to encryption, queries are padded using the ISO/IEC 7816-4 format.  The
// padding starts with a byte valued 0x80 followed by a variable number of NUL
// bytes.
//
// # Padding for client queries over UDP
//
// <client-query> <client-query-pad> must be at least <min-query-len> bytes.  If
// the length of the client query is less than <min-query-len>, the padding
// length must be adjusted in order to satisfy this requirement.
//
// <min-query-len> is a variable length, initially set to 256 bytes, and must be
// a multiple of 64 bytes.
//
// # Padding for client queries over TCP
//
// The length of <client-query-pad> is randomly chosen between 1 and 256 bytes
// (including the leading 0x80), but the total length of <client-query>
// <client-query-pad> must be a multiple of 64 bytes.
//
// For example, an originally unpadded 56-bytes DNS query can be padded as:
//	<56-bytes-query> 0x80 0x00 0x00 0x00 0x00 0x00 0x00 0x00
//	or
//	<56-bytes-query> 0x80 (0x00 * 71)
//	or
//	<56-bytes-query> 0x80 (0x00 * 135)
//	or
//	<56-bytes-query> 0x80 (0x00 * 199)

// pad performs packet padding.
func pad(packet []byte) (padded []byte) {
	// get closest divisible by 64 to <packet-len> + 1 byte for 0x80.
	minQuestionSize := len(packet) + 1 + (64 - (len(packet)+1)%64)

	// padded size can't be less than minUDPQuestionSize.
	if minUDPQuestionSize > minQuestionSize {
		minQuestionSize = minUDPQuestionSize
	}

	packet = append(packet, 0x80)
	for len(packet) < minQuestionSize {
		packet = append(packet, 0)
	}

	return packet
}

// unpad removes padding bytes from packet.
func unpad(packet []byte) (unpadded []byte, err error) {
	for i := len(packet); ; {
		if i == 0 {
			return nil, ErrInvalidPadding
		}

		i--
		if packet[i] == 0x80 {
			if i < minDNSPacketSize {
				return nil, ErrInvalidPadding
			}

			return packet[:i], nil
		} else if packet[i] != 0x00 {
			return nil, ErrInvalidPadding
		}
	}
}

// computeSharedKey computes a shared key.  secretKey and publicKey must not
// be nil.
func computeSharedKey(
	cryptoConstruction CryptoConstruction,
	secretKey *[KeySize]byte,
	publicKey *[KeySize]byte,
) (sharedKey [KeySize]byte, err error) {
	switch cryptoConstruction {
	case XChacha20Poly1305:
		sharedKey, err = xsecretbox.SharedKey(*secretKey, *publicKey)
		if err != nil {
			return sharedKey, err
		}

		return sharedKey, nil
	case XSalsa20Poly1305:
		box.Precompute(&sharedKey, publicKey, secretKey)

		return sharedKey, nil
	}

	return [KeySize]byte{}, ErrESVersion
}
