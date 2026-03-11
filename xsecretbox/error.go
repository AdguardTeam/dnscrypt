package xsecretbox

import "github.com/AdguardTeam/golibs/errors"

const (
	// errWeakPublicKey is returned when the computed X25519 shared secret is
	// zero.
	errWeakPublicKey errors.Error = "weak public key"

	// errCipherTextTooShort is returned when ciphertext is shorter than
	// [TagSize].
	errCipherTextTooShort errors.Error = "ciphertext is too short"

	// errCipherTextAuthenticationFail is returned when the authentication tag
	// of the ciphertext is invalid.
	errCipherTextAuthenticationFail errors.Error = "ciphertext authentication failed"
)
