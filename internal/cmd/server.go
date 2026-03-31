package cmd

import (
	"flag"
	"fmt"
	"net"
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

// Indexes to help with the [serverCommandLineOptions] initialization.
const (
	configIdx = iota
	forwardIdx
	listenIdx
	upstreamTimeoutIdx
	verboseIdx
)

// serverCommandLineOptions are all command-line options currently supported by
// DNSCrypt.
var serverCommandLineOptions = []*commandLineOption{
	configIdx: {
		defaultValue: "",
		description:  "Path to the server configuration file.",
		long:         "config",
		short:        "c",
		valueType:    "path",
	},

	forwardIdx: {
		defaultValue: netip.MustParseAddrPort("94.140.14.140:53"),
		description:  "Default upstream for server.",
		long:         "forward",
		short:        "f",
		valueType:    "addr",
	},

	listenIdx: {
		defaultValue: []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:443")},
		description:  "Server listening addresses.",
		long:         "listen",
		short:        "l",
		valueType:    "addr",
	},

	upstreamTimeoutIdx: {
		defaultValue: 10 * time.Second,
		description:  "Timeout for server to request upstream.",
		long:         "timeout",
		short:        "t",
		valueType:    "",
	},

	verboseIdx: {
		defaultValue: false,
		description:  "Enable verbose logging.",
		long:         "verbose",
		short:        "v",
		valueType:    "",
	},
}

// type check
var _ validate.Interface = (*serverOptions)(nil)

// Validate implements the [validate.Interface] interface for *serverOptions.
func (opts *serverOptions) Validate() (err error) {
	return validate.NotEmpty("config", opts.confFile)
}

// parseServerOptions parses command-line options for the server action.  opts
// must not be nil.
func parseServerOptions(args []string, opts *options) (err error) {
	flags := flag.NewFlagSet(actionServer, flag.ContinueOnError)

	opts.forward = serverCommandLineOptions[forwardIdx].defaultValue.(netip.AddrPort)

	for idx, fieldPtr := range []any{
		configIdx:          &opts.confFile,
		forwardIdx:         &opts.forward,
		listenIdx:          &opts.listenAddrs,
		upstreamTimeoutIdx: &opts.upstreamTimeout,
		verboseIdx:         &opts.verbose,
	} {
		addOption(flags, fieldPtr, serverCommandLineOptions[idx])
	}

	err = flags.Parse(args)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	if len(opts.listenAddrs) == 0 {
		opts.listenAddrs = serverCommandLineOptions[listenIdx].defaultValue.([]netip.AddrPort)
	}

	return nil
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

// startListeners starts TCP and UDP listeners on all the provided addresses.
// sigHdlr must not be nil.  The elements of addrs must be valid.
func startListeners(
	addrs []netip.AddrPort,
	sigHdlr *service.SignalHandler,
) (tcp []net.Listener, udp []*net.UDPConn, err error) {
	for _, addr := range addrs {
		var tcpListener net.Listener
		tcpListener, err = net.ListenTCP("tcp", net.TCPAddrFromAddrPort(addr))
		if err != nil {
			return nil, nil, fmt.Errorf("listening tcp: %w", err)
		}

		tcp = append(tcp, tcpListener)
		tcpShutdowner := service.NewCloserShutdowner(tcpListener)
		sigHdlr.AddService(service.NewShutdownService(tcpShutdowner))

		var udpConn *net.UDPConn
		udpConn, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr))
		if err != nil {
			return nil, nil, fmt.Errorf("listening udp: %w", err)
		}

		udp = append(udp, udpConn)
		udpShutdowner := service.NewCloserShutdowner(udpConn)
		sigHdlr.AddService(service.NewShutdownService(udpShutdowner))
	}

	return tcp, udp, nil
}
