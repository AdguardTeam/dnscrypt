package cmd

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/validate"
	"go.yaml.in/yaml/v4"
)

// serverOptions contains options for the server command.
type serverOptions struct {
	// confFile is a path to the configuration file.
	confFile string

	// forward is the upstream address for forwarding DNS queries.
	forward netip.AddrPort

	// listenAddrs is the list of addresses on which the server should listen.
	listenAddrs []netip.AddrPort

	// upstreamTimeout is the timeout for the server to request upstream.
	upstreamTimeout time.Duration
}

// type check
var _ validate.Interface = (*serverOptions)(nil)

// Validate implements the [validate.Interface] interface for *serverOptions.
func (opts *serverOptions) Validate() (err error) {
	errs := []error{
		validate.NotNegative("timeout", opts.upstreamTimeout),
		validate.NotEmpty("config", opts.confFile),
	}

	return errors.Join(errs...)
}

// Indexes to help with the [serverCommandLineOptions] initialization.
const (
	optIdxServerConfig = iota
	optIdxServerForward
	optIdxServerListen
	optIdxServerUpstreamTimeout
)

// serverCommandLineOptions are all command-line options currently supported by
// DNSCrypt server.
var serverCommandLineOptions = []*commandLineOption{
	optIdxServerConfig: {
		defaultValue: "config.yaml",
		description:  "Path to the server configuration file.",
		long:         "config",
		short:        "c",
		valueType:    "path",
	},

	optIdxServerForward: {
		defaultValue: netip.MustParseAddrPort("94.140.14.140:53"),
		description:  "Default upstream for server.",
		long:         "forward",
		short:        "f",
		valueType:    "addr",
	},

	optIdxServerListen: {
		defaultValue: []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:443")},
		description:  "Server listening addresses.",
		long:         "listen",
		short:        "l",
		valueType:    "addr",
	},

	optIdxServerUpstreamTimeout: {
		defaultValue: 10 * time.Second,
		description:  "Timeout for server to request upstream.",
		long:         "timeout",
		short:        "t",
		valueType:    "duration",
	},
}

// addServerOptions adds [serverCommandLineOptions] to flags.  flags and opts
// must not be nil.
func addServerOptions(flags *flag.FlagSet, opts *serverOptions) {
	opts.forward = serverCommandLineOptions[optIdxServerForward].defaultValue.(netip.AddrPort)

	for idx, fieldPtr := range []any{
		optIdxServerConfig:          &opts.confFile,
		optIdxServerForward:         &opts.forward,
		optIdxServerListen:          &opts.listenAddrs,
		optIdxServerUpstreamTimeout: &opts.upstreamTimeout,
	} {
		addOption(flags, fieldPtr, serverCommandLineOptions[idx])
	}
}

// parseConfig parses the server configuration file.
func parseConfig(path string) (c *dnscrypt.ResolverConfig, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config file: %w", err)
	}
	defer func() {
		err = errors.WithDeferred(err, file.Close())
	}()

	rc := &dnscrypt.ResolverConfig{}
	err = yaml.NewDecoder(file).Decode(rc)
	if err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	return rc, nil
}

// runServerOnAddr initializes and starts the DNSCrypt server for the given
// protocol on the provided address, and registers the created server in
// sigHdlr.  All arguments must not be nil.  c must be valid.
func runServerOnAddr(
	ctx context.Context,
	sigHdlr *service.SignalHandler,
	addr netip.AddrPort,
	c *dnscrypt.ServerConfig,
	proto dnscrypt.Proto,
) (err error) {
	var s *dnscrypt.Server
	s, err = dnscrypt.NewServer(&dnscrypt.ServerConfig{
		Logger:       c.Logger.With("listen_addr", addr.String()),
		ProviderName: c.ProviderName,
		ResolverCert: c.ResolverCert,
		Handler:      c.Handler,
		Addr:         addr,
		Proto:        proto,
	})
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	err = s.Start(ctx)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	sigHdlr.AddService(s)

	return nil
}
