package dnscrypt

import (
	"cmp"
	"net"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
)

// testTimeout is a common timeout for tests.
const testTimeout = time.Second

// testLogger is a common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

// newTestClient *Client initialized with fields from conf.  All the missing
// values will be replaced with defaults.
func newTestClient(conf *ClientConfig) (c *Client) {
	conf = cmp.Or(conf, &ClientConfig{})

	return &Client{
		logger:  cmp.Or(conf.Logger, testLogger),
		proto:   cmp.Or(conf.Proto, ProtoUDP),
		udpSize: cmp.Or(conf.UDPSize, dns.MinMsgSize),
		dialer:  &net.Dialer{},
	}
}
