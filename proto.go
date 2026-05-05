package dnscrypt

import (
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
)

// Proto represents the base network protocol.
type Proto string

const (
	// ProtoTCP represents the TCP protocol.
	ProtoTCP Proto = "tcp"

	// ProtoUDP represents the UDP protocol.
	ProtoUDP Proto = "udp"
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
			[]Proto{ProtoTCP, ProtoUDP},
		)
	}
}
