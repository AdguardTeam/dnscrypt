package cmd

import (
	"flag"
	"net/netip"
	"strings"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/golibs/stringutil"
	"github.com/ameshkov/dnsstamps"
)

// addrPortValue is an AddrPort that can be defined as a flag for
// [flag.FlagSet].
type addrPortValue netip.AddrPort

// type check
var _ flag.Value = (*addrPortValue)(nil)

// Set implements the [flag.Value] interface for *addrPortValue.
func (a *addrPortValue) Set(s string) (err error) {
	v, err := netip.ParseAddrPort(s)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	*a = addrPortValue(v)

	return nil
}

// String implements the [flag.Value] interface for *addrPortValue.
func (a *addrPortValue) String() (out string) {
	return netip.AddrPort(*a).String()
}

// addrPortSliceValue represents a struct with a slice of [netip.AddrPort]
// values that can be defined as a flag for [flag.FlagSet].
type addrPortSliceValue struct {
	// values is the pointer to a slice of addrPort to store parsed values.
	values *[]netip.AddrPort

	// isSet is false until the corresponding flag is met for the first time.
	// When the flag is found, the default value is overwritten with zero value.
	isSet bool
}

// newAddrPortSliceValue returns a pointer to addrPortSliceValue with the given
// value.  p must not be nil.
func newAddrPortSliceValue(p *[]netip.AddrPort) (out *addrPortSliceValue) {
	return &addrPortSliceValue{
		values: p,
		isSet:  false,
	}
}

// type check
var _ flag.Value = (*addrPortSliceValue)(nil)

// Set implements the [flag.Value] interface for *addrPortSliceValue.  a.values
// must not be nil.
func (a *addrPortSliceValue) Set(s string) (err error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	if !a.isSet {
		a.isSet = true
		*a.values = []netip.AddrPort{}
	}

	*a.values = append(*a.values, addr)

	return nil
}

// String implements the [flag.Value] interface for *addrPortSliceValue.
func (a *addrPortSliceValue) String() (out string) {
	if a == nil || a.values == nil {
		return ""
	}

	sb := &strings.Builder{}
	for idx, v := range *a.values {
		if idx > 0 {
			stringutil.WriteToBuilder(sb, ",")
		}

		stringutil.WriteToBuilder(sb, v.String())
	}

	return sb.String()
}

// protoValue is a Proto that can be defined as a flag for [flag.FlagSet].
type protoValue dnscrypt.Proto

// type check
var _ flag.Value = (*protoValue)(nil)

// Set implements the [flag.Value] interface for *protoValue.
func (p *protoValue) Set(s string) (err error) {
	v, err := dnscrypt.ProtoFromString(s)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	*p = protoValue(v)

	return nil
}

// String implements the [flag.Value] interface for *protoValue.
func (p *protoValue) String() (out string) {
	return string(*p)
}

// serverStampValue is a ServerStamp that can be defined as a flag for
// [flag.FlagSet].
type serverStampValue dnsstamps.ServerStamp

// type check
var _ flag.Value = (*serverStampValue)(nil)

// Set implements the [flag.Value] interface for *serverStampValue.
func (s *serverStampValue) Set(str string) (err error) {
	v, err := dnsstamps.NewServerStampFromString(str)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	*s = serverStampValue(v)

	return nil
}

// String implements the [flag.Value] interface for *serverStampValue.
func (s *serverStampValue) String() (out string) {
	stamp := dnsstamps.ServerStamp(*s)

	return stamp.String()
}
