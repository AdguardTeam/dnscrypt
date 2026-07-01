// Package dnscrypttest contains common testing constants and utilities.
package dnscrypttest

import (
	"net/netip"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

const (
	// Timeout is a common timeout for tests.
	Timeout = time.Second

	// TTL is a common DNS record TTL value that is used for testing.
	TTL = 5 * time.Minute

	// Hostname is a common hostname for tests.
	Hostname = "test.example"

	// FQDN is a common FQDN value for tests.  It is FQDN for [Hostname].
	FQDN = Hostname + "."
)

var (
	// Logger is a common logger for tests.
	Logger = slogutil.NewDiscardLogger()

	// testIPv4 is a common IPv4 address that is used for testing.
	IPv4 = netip.MustParseAddr("192.0.2.0")
)
