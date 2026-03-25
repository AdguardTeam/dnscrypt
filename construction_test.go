package dnscrypt_test

import (
	"strings"
	"testing"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/stretchr/testify/assert"
)

func TestCryptoConstruction_String(t *testing.T) {
	testCases := []struct {
		want  string
		given dnscrypt.CryptoConstruction
	}{{
		want:  "XSalsa20Poly1305",
		given: dnscrypt.XSalsa20Poly1305,
	}, {
		want:  "XChacha20Poly1305",
		given: dnscrypt.XChacha20Poly1305,
	}, {
		want:  "Unknown",
		given: 42,
	}}

	for _, tc := range testCases {
		t.Run(strings.ToLower(tc.want), func(t *testing.T) {
			assert.Equal(t, tc.want, tc.given.String())
		})
	}
}
