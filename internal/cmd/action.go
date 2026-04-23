package cmd

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
)

// actionName is a convenient alias for command-line action names.
type actionName = string

// Available actions.
const (
	actionConvert  actionName = "convert"
	actionGenerate actionName = "generate"
	actionLookup   actionName = "lookup"
	actionServer   actionName = "server"
	actionUnknown  actionName = ""
)

// commandLineAction contains information about a single action.
type commandLineAction struct {
	name        actionName
	description string
	options     []*commandLineOption
}

// actions is the list of all the available actions.
var actions = []*commandLineAction{{
	name:        actionServer,
	description: "Start DNSCrypt server",
	options:     serverCommandLineOptions,
}, {
	name:        actionLookup,
	description: "Perform DNS lookup via DNSCrypt",
	options:     lookupCommandOptions,
}, {
	name:        actionGenerate,
	description: "Generate DNSCrypt resolver config",
	options:     generateCommandLineOptions,
}, {
	name:        actionConvert,
	description: "Convert dnscrypt-wrapper keys to DNSCrypt resolver config",
	options:     convertCommandLineOptions,
}}

// runAction runs the given action with the given options and decides whether
// the application should exit afterwards.  opts must not be nil.
func runAction(ctx context.Context, action actionName, opts *options) (exit bool, err error) {
	switch action {
	case actionConvert:
		err = convert(ctx, opts.convertOptions)
	case actionGenerate:
		err = generate(ctx, opts.generateOptions)
	case actionLookup:
		err = lookup(ctx, opts.lookupOptions)
	case actionServer:
		// NOTE: Server action is handled later, right inside the [Main]
		// function.
		return false, nil
	default:
		panic(fmt.Errorf("action: %w: %q", errors.ErrBadEnumValue, action))
	}

	return true, errors.Annotate(err, "performing action: %q: %w", action)
}
