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
	"golang.org/x/crypto/curve25519"
)

// convertOptions contains options for the convert command.
type convertOptions struct {
	// providerName is the DNSCrypt provider name.
	providerName string

	// out is the path to the resulting config file.
	out string

	// privateKeyPath is the path to the file containing server private key.
	privateKeyPath string

	// resolverSecretPath is the path to the file containing short-term privacy
	// key for encrypting/decrypting DNS queries.
	resolverSecretPath string

	// ttl is the certificate's time to live.
	ttl time.Duration
}

// type check
var _ validate.Interface = (*convertOptions)(nil)

// Validate implements the [validate.Interface] interface for *convertOptions.
func (opts *convertOptions) Validate() (err error) {
	errs := []error{
		validate.NotNegative("ttl", opts.ttl),
		validate.NotEmpty("private-key", opts.privateKeyPath),
		validate.NotEmpty("resolver-secret", opts.resolverSecretPath),
		validate.NotEmpty("provider-name", opts.providerName),
		validate.NotEmpty("out", opts.out),
	}

	return errors.Join(errs...)
}

// Indexes to help with the [convertCommandLineOptions] initialization.
const (
	optIdxConvertProviderName = iota
	optIdxConvertOut
	optIdxConvertPrivateKey
	optIdxConvertResolverSecret
	optIdxConvertTTL
)

// convertCommandLineOptions are the command-line options currently supported by
// convert action.
var convertCommandLineOptions = []*commandLineOption{
	optIdxConvertProviderName: {
		defaultValue: "",
		description:  "DNSCrypt provider name.",
		long:         "provider-name",
		short:        "pn",
		valueType:    "",
	},

	optIdxConvertOut: {
		defaultValue: "config.yaml",
		description:  "Output file path.",
		long:         "out",
		short:        "o",
		valueType:    "path",
	},

	optIdxConvertPrivateKey: {
		defaultValue: "",
		description:  "Path to file with server private key.",
		long:         "private-key",
		short:        "pk",
		valueType:    "path",
	},

	optIdxConvertResolverSecret: {
		defaultValue: "",
		description:  "Path to file with short-term privacy key.",
		long:         "resolver-secret",
		short:        "r",
		valueType:    "path",
	},

	optIdxConvertTTL: {
		defaultValue: defaultCertTTL,
		description:  "Certificate time-to-live.",
		long:         "ttl",
		short:        "t",
		valueType:    "duration",
	},
}

// addConvertOptions adds [convertCommandLineOptions] to flags.  flags and opts
// must not be nil.
func addConvertOptions(flags *flag.FlagSet, opts *convertOptions) {
	for idx, fieldPtr := range []any{
		optIdxConvertProviderName:   &opts.providerName,
		optIdxConvertOut:            &opts.out,
		optIdxConvertPrivateKey:     &opts.privateKeyPath,
		optIdxConvertResolverSecret: &opts.resolverSecretPath,
		optIdxConvertTTL:            &opts.ttl,
	} {
		addOption(flags, fieldPtr, convertCommandLineOptions[idx])
	}
}

// convert generates [dnscrypt.ResolverConfig] using keys generated with
// dnscrypt-wrapper and saves the result to the configured file.  ctx must
// contain a logger accessible with [slogutil.LoggerFromContext].
func convert(ctx context.Context, opts convertOptions) (err error) {
	err = opts.Validate()
	if err != nil {
		return fmt.Errorf("validating options: %w", err)
	}

	l := slogutil.MustLoggerFromContext(ctx)

	l.InfoContext(ctx, "generating resolver config")
	privateKeyBytes, err := os.ReadFile(opts.privateKeyPath)
	if err != nil {
		return fmt.Errorf("reading private key: %w", err)
	}

	resolverSecretBytes, err := os.ReadFile(opts.resolverSecretPath)
	if err != nil {
		return fmt.Errorf("reading resolver secret: %w", err)
	}

	privateKey := ed25519.PrivateKey(privateKeyBytes)
	err = validate.Equal("private key length", len(privateKey), ed25519.PrivateKeySize)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	publicKey := privateKey.Public()
	rawPublicKey, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		panic(fmt.Errorf("bad type for public key: %T(%[1]v)", publicKey))
	}

	resolverSk := ed25519.PrivateKey(resolverSecretBytes)
	err = validate.Equal("resolver secret length", len(resolverSecretBytes), dnscrypt.KeySize)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	resolverPk := getResolverPublicKey(resolverSk)

	config := &dnscrypt.ResolverConfig{
		ESVersion:      dnscrypt.XSalsa20Poly1305,
		CertificateTTL: opts.ttl,
		ProviderName:   opts.providerName,
		PrivateKey:     dnscrypt.HexEncodeKey(privateKeyBytes),
		PublicKey:      dnscrypt.HexEncodeKey(rawPublicKey),
		ResolverSk:     dnscrypt.HexEncodeKey(resolverSecretBytes),
		ResolverPk:     dnscrypt.HexEncodeKey(resolverPk),
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

// getResolverPublicKey calculates public key from private key.
func getResolverPublicKey(key ed25519.PrivateKey) (public ed25519.PublicKey) {
	var (
		resolverSk [dnscrypt.KeySize]byte
		resolverPk [dnscrypt.KeySize]byte
	)

	copy(resolverSk[:], key)
	curve25519.ScalarBaseMult(&resolverPk, &resolverSk)

	return resolverPk[:]
}
