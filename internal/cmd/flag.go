package cmd

import (
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/dnscrypt/internal/version"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/ameshkov/dnsstamps"
)

// minArgs is the minimum valid number of command-line arguments.
const minArgs = 1

// options contain all the command-specific and common options.
type options struct {
	convertOptions
	generateOptions
	lookupOptions
	serverOptions
	commonOptions
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

// commonOptions contains options that can be used regardless of the chosen
// action.
type commonOptions struct {
	// verbose flag defines whether verbose logging is enabled.
	verbose bool

	// help flag defines whether a help message must be printed.
	help bool

	// version flag determines whether the DNSCrypt version should be printed.
	version bool
}

// Indexes to help with the [commonCommandLineOptions] initialization.
const (
	optIdxVerbose = iota
	optIdxHelp
	optIdxVersion
)

// commonCommandLineOptions are the common command-line options that are
// currently supported by all DNSCrypt actions.
var commonCommandLineOptions = []*commandLineOption{
	optIdxVerbose: {
		defaultValue: false,
		description:  "Enable verbose logging",
		long:         "verbose",
		short:        "v",
		valueType:    "",
	},

	optIdxHelp: {
		defaultValue: false,
		description:  "Show help message",
		long:         "help",
		short:        "h",
		valueType:    "",
	},

	optIdxVersion: {
		defaultValue: false,
		description:  "Show version information",
		long:         "version",
		short:        "",
		valueType:    "",
	},
}

// addCommonOptions adds [commonCommandLineOptions] to flags.  flags and opts
// must not be nil.
func addCommonOptions(flags *flag.FlagSet, opts *options) {
	for idx, fieldPtr := range []any{
		optIdxVerbose: &opts.verbose,
		optIdxHelp:    &opts.help,
		optIdxVersion: &opts.version,
	} {
		addOption(flags, fieldPtr, commonCommandLineOptions[idx])
	}
}

// parseOptions parses the command-line options for DNSCrypt.
func parseOptions() (opts *options, action actionName, err error) {
	args := os.Args[1:]
	if len(args) < minArgs {
		usage("")

		os.Exit(osutil.ExitCodeArgumentError)
	}

	opts = &options{}
	action = args[0]

	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	addCommonOptions(flags, opts)

	switch action {
	case actionConvert:
		addConvertOptions(flags, &opts.convertOptions)
	case actionGenerate:
		addGenerateOptions(flags, &opts.generateOptions)
	case actionLookup:
		addLookupOptions(flags, &opts.lookupOptions)
	case actionServer:
		addServerOptions(flags, &opts.serverOptions)
	default:
		action = actionUnknown
	}

	flags.Usage = func() {
		usage(action)
	}

	if action == actionUnknown {
		err = flags.Parse(args)
	} else {
		err = flags.Parse(args[1:])
	}

	if err != nil {
		return nil, action, err
	}

	return opts, action, nil
}

// defineFlag defines a flag with specified setFlag function.  All arguments
// must not be nil.
func defineFlag[T any](
	fieldPtr *T,
	o *commandLineOption,
	setFlag func(p *T, name string, value T, usage string),
) {
	defaultValue, ok := o.defaultValue.(T)
	if !ok {
		panic(fmt.Errorf("bad type for default value: %T(%[1]v)", o.defaultValue))
	}

	setFlag(fieldPtr, o.long, defaultValue, o.description)
	if o.short != "" {
		setFlag(fieldPtr, o.short, defaultValue, o.description)
	}
}

// defineFlagVar defines a flag with the specified [flag.Value] value.  All
// arguments must not be nil.
func defineFlagVar[T any](fieldPtr *T, flags *flag.FlagSet, value flag.Value, o *commandLineOption) {
	defaultValue, ok := o.defaultValue.(T)
	if !ok {
		panic(fmt.Errorf("bad type for default value: %T(%[1]v)", o.defaultValue))
	}

	*fieldPtr = defaultValue

	flags.Var(value, o.long, o.description)
	if o.short != "" {
		flags.Var(value, o.short, o.description)
	}
}

// addOption adds the command-line option described by o to flags using fieldPtr
// as the pointer to the value.  All arguments must not be nil.
func addOption(flags *flag.FlagSet, fieldPtr any, o *commandLineOption) {
	switch fieldPtr := fieldPtr.(type) {
	case *bool:
		defineFlag(fieldPtr, o, flags.BoolVar)
	case *string:
		defineFlag(fieldPtr, o, flags.StringVar)
	case *time.Duration:
		defineFlag(fieldPtr, o, flags.DurationVar)
	case *netip.AddrPort:
		defineFlagVar(fieldPtr, flags, (*addrPortValue)(fieldPtr), o)
	case *[]netip.AddrPort:
		defineFlagVar(fieldPtr, flags, newAddrPortSliceValue(fieldPtr), o)
	case *dnscrypt.Proto:
		defineFlagVar(fieldPtr, flags, (*protoValue)(fieldPtr), o)
	case *dnsstamps.ServerStamp:
		defineFlagVar(fieldPtr, flags, (*serverStampValue)(fieldPtr), o)
	default:
		panic(fmt.Errorf("unexpected field pointer type %T", fieldPtr))
	}
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

// processCommonOpts processes the parsed common options and decides whether the
// application should exit, as well as determining the exit code.  opts must not
// be nil.
func processCommonOpts(action actionName, opts *options) (exit bool, code osutil.ExitCode) {
	if opts.version {
		fmt.Printf("DNSCrypt %s\n", version.Version())

		return true, osutil.ExitCodeSuccess
	}

	if opts.help {
		usage(action)

		return true, osutil.ExitCodeSuccess
	}

	if action == actionUnknown {
		usage(action)

		return true, osutil.ExitCodeArgumentError
	}

	return false, 0
}

// usage prints a usage message for the specified action.
func usage(action actionName) {
	if action == actionUnknown {
		generalUsage()

		return
	}

	actionUsage(action)
}

// generalUsage prints the general usage message.
func generalUsage() {
	fmt.Printf("Usage: dnscrypt <command> [options]\n\n")
	fmt.Printf("Commands:\n")

	for _, action := range actions {
		fmt.Printf("  %-28s %s\n", action.name, action.description)
	}

	fmt.Printf("\nCommon Options:\n")
	printOptions(commonCommandLineOptions)

	fmt.Printf("\nRun 'dnscrypt <command> --help' for command-specific options.\n")
}

// actionUsage prints the usage message for a specific action.
func actionUsage(action actionName) {
	var actionData *commandLineAction
	for i := range actions {
		if actions[i].name == action {
			actionData = actions[i]

			break
		}
	}

	if actionData == nil {
		generalUsage()

		return
	}

	fmt.Printf("Usage: dnscrypt %s [options]\n\n", actionData.name)
	fmt.Printf("%s\n\n", actionData.description)

	fmt.Printf("Options:\n")
	printOptions(actionData.options)
	fmt.Printf("\n")

	fmt.Printf("Common Options:\n")
	printOptions(commonCommandLineOptions)
}

// printOptions prints command-line options info.
func printOptions(options []*commandLineOption) {
	opts := slices.Clone(options)
	slices.SortStableFunc(opts, func(a, b *commandLineOption) (res int) {
		return strings.Compare(a.long, b.long)
	})

	for _, o := range opts {
		usageLine(o)

		if shouldIncludeDefault(o.defaultValue) {
			fmt.Printf("    \t%s (default: %v)\n", o.description, o.defaultValue)
		} else {
			fmt.Printf("    \t%s\n", o.description)
		}
	}
}

// shouldIncludeDefault returns true if this default value should be printed.
func shouldIncludeDefault(v any) (ok bool) {
	switch v := v.(type) {
	case bool:
		return v
	case string, dnscrypt.Proto:
		return v != ""
	default:
		return v == nil
	}
}

// usageLine prints the usage line for the provided command-line option.  o must
// not be nil.
func usageLine(o *commandLineOption) {
	if o.short == "" {
		if o.valueType == "" {
			fmt.Printf("  --%s\n", o.long)
		} else {
			fmt.Printf("  --%s=%s\n", o.long, o.valueType)
		}

		return
	}

	if o.valueType == "" {
		fmt.Printf("  --%s/-%s\n", o.long, o.short)
	} else {
		fmt.Printf("  --%[1]s=%[3]s/-%[2]s %[3]s\n", o.long, o.short, o.valueType)
	}
}
