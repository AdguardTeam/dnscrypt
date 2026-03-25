package dnscrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnpackTxtString(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input string
		want  []byte
	}{{
		name:  "no_escape_sequences",
		input: "foo_bar",
		want:  []byte("foo_bar"),
	}, {
		name:  "with_escape_sequences",
		input: "\\t\\r\\n",
		want:  []byte{'\t', '\r', '\n'},
	}, {
		name:  "ddd",
		input: "\\097\\098\\099",
		want:  []byte("abc"),
	}, {
		name:  "backslash_in_the_end",
		input: "foo_bar\\",
		want:  []byte("foo_bar"),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := unpackTxtString(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}
