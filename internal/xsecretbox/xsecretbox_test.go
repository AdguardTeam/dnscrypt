package xsecretbox_test

import (
	"testing"

	"github.com/AdguardTeam/dnscrypt/internal/xsecretbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretbox(t *testing.T) {
	t.Parallel()

	key := [32]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	nonce := [24]byte{23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	src := []byte{42, 42, 42, 42, 42, 42, 42, 42, 42, 42}

	dst := xsecretbox.Seal(nil, nonce[:], src[:], key[:])
	dec, err := xsecretbox.Open(nil, nonce[:], dst[:], key[:])
	require.NoError(t, err)
	assert.Equal(t, src, dec)

	dst[0]++
	_, err = xsecretbox.Open(nil, nonce[:], dst[:], key[:])
	require.Error(t, err)

	_, _ = xsecretbox.SharedKey(key, key)
}
