// Package cmd is the DNSCrypt entry point.
package cmd

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"os"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/dnscrypt/internal/forward"
	"github.com/AdguardTeam/dnscrypt/internal/version"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
)

const (
	// hexEncodedPrivateKeyLength is the length of a valid hex-encoded private
	// key.
	hexEncodedPrivateKeyLength = 2 * ed25519.PrivateKeySize

	// hexEncodedPublicKeyLength is the length of a valid hex-encoded public
	// key.
	hexEncodedPublicKeyLength = 2 * dnscrypt.KeySize

	// defaultCertTTL is the default time-to-live value for generated
	// certificates.
	defaultCertTTL = 365 * timeutil.Day
)

// TODO(f.setrakov): Move to dcos.
const (
	// defaultWOFlags are the default flags for write-only operations.
	defaultWOFlags int = os.O_CREATE | os.O_WRONLY | os.O_TRUNC

	// defaultPerm is the default set of permissions for non-executable files.
	defaultPerm = 0o600
)

// Main is the entrypoint of DNSCrypt.
func Main() {
	ctx := context.Background()

	opts, action, err := parseOptions()
	check(ctx, osutil.ExitCodeArgumentError, err)

	logger := newBaseLogger(opts)
	ctx = slogutil.ContextWithLogger(ctx, logger)

	shouldExit, code := processCommonOpts(action, opts)
	if shouldExit {
		os.Exit(code)
	}

	exit, err := runAction(ctx, action, opts)
	check(ctx, osutil.ExitCodeFailure, err)
	if exit {
		os.Exit(osutil.ExitCodeSuccess)
	}

	err = errors.Annotate(opts.serverOptions.Validate(), "validating options: %w")
	check(ctx, osutil.ExitCodeArgumentError, err)

	logger.InfoContext(
		ctx,
		"starting dnscrypt server",
		"pid", os.Getpid(),
		"version", version.Version(),
		"branch", version.Branch(),
		"commit_time", version.CommitTime(),
		"race", version.RaceEnabled,
		"revision", version.Revision(),
	)

	rc, err := parseConfig(opts.confFile)
	check(ctx, osutil.ExitCodeFailure, err)

	check(ctx, osutil.ExitCodeFailure, errors.Annotate(rc.Validate(), "validating config: %w"))

	cert, err := rc.NewCert()
	check(ctx, osutil.ExitCodeFailure, errors.Annotate(err, "creating certificate"))

	h := forward.NewHandler(&forward.HandlerConfig{
		Address: opts.forward,
		Client: &dns.Client{
			Timeout: opts.upstreamTimeout,
		},
	})

	s, err := dnscrypt.NewServer(&dnscrypt.ServerConfig{
		Logger:       logger,
		ProviderName: rc.ProviderName,
		ResolverCert: cert,
		Handler:      h,
	})
	check(ctx, osutil.ExitCodeFailure, err)

	sigHdlr := service.NewSignalHandler(&service.SignalHandlerConfig{
		Logger: logger,
	})

	tcp, udp, err := startListeners(opts.listenAddrs, sigHdlr)
	check(ctx, osutil.ExitCodeFailure, err)

	// TODO(f.setrakov): Use [dnscrypt.Server.Start] when implemented.
	for _, t := range tcp {
		logger.InfoContext(ctx, "running tcp listener", "addr", t.Addr())

		go func() {
			tcpErr := s.ServeTCP(ctx, t)
			if tcpErr != nil {
				logger.ErrorContext(ctx, "tcp listening failed", slogutil.KeyError, tcpErr)
			}
		}()
	}

	for _, u := range udp {
		logger.InfoContext(ctx, "running udp listener", "addr", u.LocalAddr())

		go func() {
			udpErr := s.ServeUDP(ctx, u)
			if udpErr != nil {
				logger.ErrorContext(ctx, "udp listening failed", slogutil.KeyError, udpErr)
			}
		}()
	}

	serverShutdown := service.NewShutdownService(s)
	sigHdlr.AddService(serverShutdown)

	os.Exit(sigHdlr.Handle(ctx))
}

// check writes the error to the log and exits the process with a failure code
// if the error is not nil.
func check(ctx context.Context, exitCode int, err error) {
	if err == nil {
		return
	}

	l, ok := slogutil.LoggerFromContext(ctx)
	if !ok {
		l = slog.Default()
	}

	l.ErrorContext(ctx, "fatal error", slogutil.KeyError, err)

	os.Exit(exitCode)
}
