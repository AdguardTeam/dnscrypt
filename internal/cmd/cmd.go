// Package cmd is the DNSCrypt entry point.
package cmd

import (
	"context"
	"log/slog"
	"os"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/dnscrypt/internal/forward"
	"github.com/AdguardTeam/dnscrypt/internal/version"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/miekg/dns"
)

// Main is the entrypoint of DNSCrypt.
func Main() {
	ctx := context.Background()

	opts, _, err := parseOptions()
	check(ctx, osutil.ExitCodeArgumentError, err)

	logger := newBaseLogger(opts)
	ctx = slogutil.ContextWithLogger(ctx, logger)

	// TODO(f.setrakov): Run other actions.
	err = errors.Annotate(opts.Validate(), "validating options: %w")
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
		Address: opts.forward.String(),
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

	for _, t := range tcp {
		logger.InfoContext(ctx, "running tcp listener", "addr", t.Addr())

		go func() { _ = s.ServeTCP(ctx, t) }()
	}

	for _, u := range udp {
		logger.InfoContext(ctx, "running udp listener", "addr", u.LocalAddr())

		go func() { _ = s.ServeUDP(ctx, u) }()
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
