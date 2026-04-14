package cmd

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"strings"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
)

// errInvalidRRType is returned when an invalid DNS query type is provided.
const errInvalidRRType errors.Error = "invalid rr type"

// lookupOptions contains options for the lookup command.
type lookupOptions struct {
	// publicKey is the resolver's public key.
	publicKey string

	// providerName is the resolver's provider name.
	providerName string

	// resolverAddr is the resolver's address.
	resolverAddr netip.AddrPort

	// domain is the target domain for the lookup.
	domain string

	// queryType is the target DNS resource record type.
	queryType string

	// network is the network protocol used for the lookup.
	network dnscrypt.Proto

	// stamp is the resolver's server stamp.
	stamp dnsstamps.ServerStamp
}

// type check
var _ validate.Interface = (*lookupOptions)(nil)

// Validate implements the [validate.Interface] interface for *lookupOptions.
func (opts *lookupOptions) Validate() (err error) {
	var errs []error
	errs = append(errs, validate.NotEmpty("domain", opts.domain))

	// Only validate the resolver info if the stamp is empty.
	if opts.stamp.ProviderName == "" {
		errs = append(errs, validate.NotEmpty("public-key", opts.publicKey))
		errs = append(errs, validate.NotEmpty("provider-name", opts.providerName))
		errs = append(errs, validate.NotEmpty("addr", opts.resolverAddr))
	}

	return errors.Join(errs...)
}

// Indexes to help with the [lookupCommandOptions] initialization.
const (
	optIdxLookupPublicKey = iota
	optIdxLookupProviderName
	optIdxLookupResolverAddr
	optIdxLookupDomain
	optIdxLookupQueryType
	optIdxLookupNetwork
	optIdxLookupStamp
)

// lookupCommandLineOptions are the command-line options currently supported by
// lookup action.
var lookupCommandOptions = []*commandLineOption{
	optIdxLookupPublicKey: {
		defaultValue: "",
		description:  "DNSCrypt resolver public key.",
		long:         "public-key",
		short:        "pk",
		valueType:    "",
	},

	optIdxLookupProviderName: {
		defaultValue: "",
		description:  "DNSCrypt provider name.",
		long:         "provider-name",
		short:        "pn",
		valueType:    "",
	},

	optIdxLookupResolverAddr: {
		defaultValue: netip.AddrPort{},
		description:  "Resolver address (IP[:port]).",
		long:         "addr",
		short:        "a",
		valueType:    "addr",
	},

	optIdxLookupDomain: {
		defaultValue: "",
		description:  "Domain to resolve.",
		long:         "domain",
		short:        "d",
		valueType:    "domain",
	},

	optIdxLookupQueryType: {
		defaultValue: "A",
		description:  "DNS query type.",
		long:         "type",
		short:        "t",
	},

	optIdxLookupNetwork: {
		defaultValue: dnscrypt.ProtoUDP,
		description:  "Network protocol (tcp/udp).",
		long:         "network",
		short:        "n",
		valueType:    "",
	},

	optIdxLookupStamp: {
		defaultValue: dnsstamps.ServerStamp{},
		description:  "DNSCrypt resolver stamp.",
		long:         "stamp",
		short:        "s",
		valueType:    "stamp",
	},
}

// addLookupOptions adds [lookupCommandLineOptions] to flags.  flags and opts
// must not be nil.
func addLookupOptions(flags *flag.FlagSet, opts *lookupOptions) {
	for idx, fieldPtr := range []any{
		optIdxLookupPublicKey:    &opts.publicKey,
		optIdxLookupProviderName: &opts.providerName,
		optIdxLookupResolverAddr: &opts.resolverAddr,
		optIdxLookupDomain:       &opts.domain,
		optIdxLookupQueryType:    &opts.queryType,
		optIdxLookupNetwork:      &opts.network,
		optIdxLookupStamp:        &opts.stamp,
	} {
		addOption(flags, fieldPtr, lookupCommandOptions[idx])
	}
}

// lookup performs a DNS lookup using DNSCrypt.  If the stamp option is set, it
// will be used for the lookup.  Otherwise, the lookup will be performed using
// the raw parameters.
func lookup(ctx context.Context, opts lookupOptions) (err error) {
	err = opts.Validate()
	if err != nil {
		return fmt.Errorf("validating options: %w", err)
	}

	var stamp dnsstamps.ServerStamp
	if opts.stamp.ProviderName != "" {
		stamp = opts.stamp
	} else {
		var serverPk []byte
		serverPk, err = dnscrypt.HexDecodeKey(opts.publicKey)
		if err != nil {
			return fmt.Errorf("decoding public key: %w", err)
		}

		stamp = dnsstamps.ServerStamp{
			ProviderName:  opts.providerName,
			ServerPk:      serverPk,
			ServerAddrStr: opts.resolverAddr.String(),
			Proto:         dnsstamps.StampProtoTypeDNSCrypt,
		}
	}

	c := dnscrypt.NewClient(&dnscrypt.ClientConfig{
		Proto: opts.network,
	})

	ri, err := c.DialStampContext(ctx, stamp)
	if err != nil {
		return fmt.Errorf("dialing: %w", err)
	}

	req, err := newLookupRequest(opts.domain, opts.queryType)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.ExchangeContext(ctx, req, ri)
	if err != nil {
		return fmt.Errorf("exchanging: %w", err)
	}

	fmt.Println(resp)

	return nil
}

// newLookupRequest creates a new DNS request message.
func newLookupRequest(domain, queryType string) (req *dns.Msg, err error) {
	rrType, ok := dns.StringToType[strings.ToUpper(queryType)]
	if !ok {
		return nil, errInvalidRRType
	}

	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   dns.Fqdn(domain),
			Qtype:  rrType,
			Qclass: dns.ClassINET,
		}},
	}, nil
}
