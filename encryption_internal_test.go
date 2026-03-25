package dnscrypt

import (
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

func TestPad(t *testing.T) {
	t.Parallel()

	input := []byte{1, 2, 3, 4}

	want := make([]byte, minUDPQuestionSize)
	copy(want, input)
	want[len(input)] = 0x80

	assert.Equal(t, want, pad(input))
}

func TestUnpad(t *testing.T) {
	t.Parallel()

	testСases := []struct {
		name  string
		input []byte
		want  []byte
	}{{
		name:  "valid padding",
		input: append(make([]byte, minDNSPacketSize), 0x80),
		want:  make([]byte, minDNSPacketSize),
	}, {
		name:  "no_terminator",
		input: []byte{1, 2, 3, 4},
		want:  nil,
	}, {
		name:  "too_short",
		input: []byte{1, 2, 3, 4, 0x80},
		want:  nil,
	}, {
		name:  "empty_empty",
		input: []byte{},
		want:  nil,
	}}

	for _, tc := range testСases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := unpad(tc.input)
			if tc.want == nil {
				testutil.AssertErrorMsg(t, ErrInvalidPadding.Error(), err)
			} else {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}
