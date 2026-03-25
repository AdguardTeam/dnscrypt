package dnscrypt

import "fmt"

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

// type check
var _ fmt.Stringer = (*CryptoConstruction)(nil)

// String implements the [fmt.Stringer] interface for CryptoConstruction.
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
