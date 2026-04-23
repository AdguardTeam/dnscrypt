package cmd

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/validate"
	"go.yaml.in/yaml/v4"
)

// generateOptions contains options for the generate command.
type generateOptions struct {
	// providerName is the DNSCrypt provider name.
	providerName string

	// out is the path to the resulting config file.
	out string

	// private key is the server private key.
	privateKey string

	// ttl is the certificate's time to live.
	ttl time.Duration
}

// type check
var _ validate.Interface = (*generateOptions)(nil)

// Validate implements the [validate.Interface] interface for *generateOptions.
func (opts *generateOptions) Validate() (err error) {
	errs := []error{
		validate.NotNegative("ttl", opts.ttl),
		validate.NotEmpty("provider-name", opts.providerName),
	}

	if opts.privateKey != "" {
		errs = append(
			errs,
			validate.Equal("private key length", len(opts.privateKey), hexEncodedPrivateKeyLength),
		)
	}

	return errors.Join(errs...)
}

// Indexes to help with the [generateCommandLineOptions] initialization.
const (
	optIdxGenerateProviderName = iota
	optIdxGenerateOut
	optIdxGeneratePrivateKey
	optIdxGenerateTTL
)

// generateCommandLineOptions are the command-line options currently supported
// by generate action.
var generateCommandLineOptions = []*commandLineOption{
	optIdxGenerateProviderName: {
		defaultValue: "",
		description:  "DNSCrypt provider name.",
		long:         "provider-name",
		short:        "pn",
		valueType:    "",
	},

	optIdxGenerateOut: {
		defaultValue: "config.yaml",
		description:  "Output file path.",
		long:         "out",
		short:        "o",
		valueType:    "path",
	},

	optIdxGeneratePrivateKey: {
		defaultValue: "",
		description:  "Server hex-encoded private key.",
		long:         "private-key",
		short:        "pk",
		valueType:    "",
	},

	optIdxGenerateTTL: {
		defaultValue: defaultCertTTL,
		description:  "Certificate time-to-live.",
		long:         "ttl",
		short:        "t",
		valueType:    "duration",
	},
}

// addGenerateOptions adds [generateCommandLineOptions] to flags.  flags and
// opts must not be nil.
func addGenerateOptions(flags *flag.FlagSet, opts *generateOptions) {
	for idx, fieldPtr := range []any{
		optIdxGenerateProviderName: &opts.providerName,
		optIdxGenerateOut:          &opts.out,
		optIdxGeneratePrivateKey:   &opts.privateKey,
		optIdxGenerateTTL:          &opts.ttl,
	} {
		addOption(flags, fieldPtr, generateCommandLineOptions[idx])
	}
}

// generate generates [dnscrypt.ResolverConfig] using the given options and
// saves the result to the configured file.  ctx must contain a logger
// accessible with [slogutil.LoggerFromContext].
func generate(ctx context.Context, opts generateOptions) (err error) {
	err = opts.Validate()
	if err != nil {
		return fmt.Errorf("validating options: %w", err)
	}

	l := slogutil.MustLoggerFromContext(ctx)

	l.InfoContext(ctx, "generating resolver config")
	var privateKey ed25519.PrivateKey
	if opts.privateKey == "" {
		l.InfoContext(ctx, "no private key provided, generating new one")
	} else {
		privateKey, err = dnscrypt.HexDecodeKey(opts.privateKey)
		if err != nil {
			return fmt.Errorf("decoding private key: %w", err)
		}
	}

	config, err := dnscrypt.GenerateResolverConfig(opts.providerName, privateKey, opts.ttl)
	if err != nil {
		return fmt.Errorf("generating resolver config: %w", err)
	}

	file, err := os.OpenFile(opts.out, defaultWOFlags, defaultPerm)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, file.Close()) }()

	err = yaml.NewEncoder(file).Encode(config)
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}

	l.InfoContext(ctx, "config saved", "dst", opts.out)

	return nil
}
