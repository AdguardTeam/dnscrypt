package dnscrypt

import "strings"

const (
	// escapedByteSmall contains escaped representations of bytes from 0x00
	// to 0x1F.
	escapedByteSmall = "" +
		`\000\001\002\003\004\005\006\007\008\009` +
		`\010\011\012\013\014\015\016\017\018\019` +
		`\020\021\022\023\024\025\026\027\028\029` +
		`\030\031`

	// escapedByteLarge contains escaped representations of bytes from 0x7F
	// to 0xFF.
	escapedByteLarge = `\127\128\129` +
		`\130\131\132\133\134\135\136\137\138\139` +
		`\140\141\142\143\144\145\146\147\148\149` +
		`\150\151\152\153\154\155\156\157\158\159` +
		`\160\161\162\163\164\165\166\167\168\169` +
		`\170\171\172\173\174\175\176\177\178\179` +
		`\180\181\182\183\184\185\186\187\188\189` +
		`\190\191\192\193\194\195\196\197\198\199` +
		`\200\201\202\203\204\205\206\207\208\209` +
		`\210\211\212\213\214\215\216\217\218\219` +
		`\220\221\222\223\224\225\226\227\228\229` +
		`\230\231\232\233\234\235\236\237\238\239` +
		`\240\241\242\243\244\245\246\247\248\249` +
		`\250\251\252\253\254\255`
)

// packTxtString packs a TXT string by escaping special characters.  buf must
// not be nil.
func packTxtString(buf []byte) (packed string) {
	var out strings.Builder
	out.Grow(3 + len(buf))
	for i := 0; i < len(buf); i++ {
		b := buf[i]
		switch {
		case b == '"' || b == '\\':
			out.WriteByte('\\')
			out.WriteByte(b)
		case b < ' ' || b > '~':
			out.WriteString(escapeByte(b))
		default:
			out.WriteByte(b)
		}
	}

	return out.String()
}

// escapeByte returns the \DDD escaping of b which must satisfy
// b < ' ' || b > '~'.
func escapeByte(b byte) (escaped string) {
	if b < ' ' {
		return escapedByteSmall[b*4 : b*4+4]
	}

	b -= '~' + 1

	// The cast here is needed as b*4 may overflow byte.
	return escapedByteLarge[int(b)*4 : int(b)*4+4]
}

// unpackTxtString unpacks a TXT string by unescaping special characters.
func unpackTxtString(s string) (msg []byte) {
	bs := []byte(s)
	msg = make([]byte, 0)
	for i := 0; i < len(bs); i++ {
		if bs[i] != '\\' {
			msg = append(msg, bs[i])

			continue
		}

		i++
		if i == len(bs) {
			break
		}

		if i+2 < len(bs) && isDigitSequence(bs[i:i+3]) {
			msg = append(msg, dddToByte(bs[i:]))
			i += 2

			continue
		}

		msg = append(msg, unescape(bs[i]))
	}

	return msg
}

// isDigitSequence returns true if every character in sequence is numeric.
func isDigitSequence(sequence []byte) (ok bool) {
	for _, c := range sequence {
		if c < '0' || c > '9' {
			return false
		}
	}

	return true
}

// dddToByte converts a slice of three ASCII digits into a byte value.
func dddToByte(s []byte) (res byte) {
	return (s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0')
}

// unescape returns corresponding escape-sequence by its char.  If b is not part
// of any escape sequence, b is being returned.
func unescape(b byte) (escaped byte) {
	switch b {
	case 't':
		return '\t'
	case 'r':
		return '\r'
	case 'n':
		return '\n'
	default:
		return b
	}
}
