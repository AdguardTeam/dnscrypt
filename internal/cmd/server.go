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

// type check
var _ validate.Interface = (*serverOptions)(nil)

// Validate implements the [validate.Interface] interface for *serverOptions.
func (opts *serverOptions) Validate() (err error) {
	return validate.NotEmpty("config", opts.confFile)
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
