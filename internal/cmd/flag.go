package cmd

import (
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// minArgs is the minimum valid number of command-line arguments.
const minArgs = 1

// errNotEnoughArgs is returned when cmd is launched with too few arguments.
const errNotEnoughArgs errors.Error = "not enough arguments"

// options contain all the command-specific and common options.
type options struct {
	serverOptions

	// verbose flag defines whether verbose logging is enabled.
	verbose bool

	// TODO(f.setrakov): Add help and version options.
}

// commandLineOption contains information about a command-line option: its long
// and, if there is one, short forms, the value type, the description, and the
// default value.
type commandLineOption struct {
	defaultValue any
	description  string
	long         string
	short        string
	valueType    string
}

// parseOptions parses the command-line options for DNSCrypt.
func parseOptions() (opts *options, action string, err error) {
	args := os.Args[1:]
	if len(args) < minArgs {
		// TODO(f.setrakov): Print help.
		return nil, "", errNotEnoughArgs
	}

	action = args[0]
	opts = &options{}

	// TODO(f.setrakov): Parse options for other actions.
	if action == actionServer {
		err = parseServerOptions(args[1:], opts)
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return nil, "", err
		}
	} else {
		return nil, "", fmt.Errorf("unknown action: %q", action)
	}

	return opts, action, nil
}

// addOption adds the command-line option described by o to flags using fieldPtr
// as the pointer to the value.  All arguments must not be nil.
func addOption(flags *flag.FlagSet, fieldPtr any, o *commandLineOption) {
	switch typedPtr := fieldPtr.(type) {
	case *bool:
		flags.BoolVar(typedPtr, o.long, o.defaultValue.(bool), o.description)
		if o.short != "" {
			flags.BoolVar(typedPtr, o.short, o.defaultValue.(bool), o.description)
		}
	case *string:
		flags.StringVar(typedPtr, o.long, o.defaultValue.(string), o.description)
		if o.short != "" {
			flags.StringVar(typedPtr, o.short, o.defaultValue.(string), o.description)
		}
	case *time.Duration:
		flags.DurationVar(typedPtr, o.long, o.defaultValue.(time.Duration), o.description)
		if o.short != "" {
			flags.DurationVar(typedPtr, o.short, o.defaultValue.(time.Duration), o.description)
		}
	case *[]netip.AddrPort, *netip.AddrPort:
		addCustomTypeOption(flags, fieldPtr, o)
	default:
		panic(fmt.Errorf("unexpected field pointer type %T", typedPtr))
	}
}

// addCustomTypeOption adds the command-line option described by o to flags
// using fieldPtr as the pointer to the value.  Unlike [addOption], this
// function works with types that do not have standard flag-adding functions.
// All arguments must not be nil.
func addCustomTypeOption(flags *flag.FlagSet, fieldPtr any, o *commandLineOption) {
	switch fieldPtr := fieldPtr.(type) {
	case *[]netip.AddrPort:
		flags.Func(o.long, o.description, func(s string) (err error) {
			return setAddrPortSliceFlag(fieldPtr, s)
		})
		if o.short != "" {
			flags.Func(o.short, o.description, func(s string) (err error) {
				return setAddrPortSliceFlag(fieldPtr, s)
			})
		}
	case *netip.AddrPort:
		flags.Func(o.long, o.description, func(s string) (err error) {
			*fieldPtr, err = netip.ParseAddrPort(s)

			return errors.Annotate(err, "parsing addr: %w")
		})
		if o.short != "" {
			flags.Func(o.short, o.description, func(s string) (err error) {
				*fieldPtr, err = netip.ParseAddrPort(s)

				return errors.Annotate(err, "parsing addr: %w")
			})
		}
	default:
		panic(fmt.Errorf("unexpected slice field pointer type %T", fieldPtr))
	}
}

// setUintSliceFlag parses and appends a netip.AddrPort value to the slice.  ptr
// must not be nil.
func setAddrPortSliceFlag(ptr *[]netip.AddrPort, s string) (err error) {
	ip, err := netip.ParseAddrPort(s)
	if err != nil {
		return fmt.Errorf("parsing addr: %w", err)
	}

	*ptr = append(*ptr, ip)

	return nil
}

// newBaseLogger constructs a base logger based on the command-line options.
// opts must not be nil.
func newBaseLogger(opts *options) (baseLogger *slog.Logger) {
	lvl := slog.LevelInfo
	if opts.verbose {
		lvl = slog.LevelDebug
	}

	return slogutil.New(&slogutil.Config{
		// TODO(f.setrakov): Get from config.
		Format: slogutil.FormatText,
		Level:  lvl,
		// TODO(f.setrakov): Get from config.
		AddTimestamp: true,
	})
}
