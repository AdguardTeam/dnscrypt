package dnscrypt

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// TODO(f.setrakov): Remove external tests.
func TestInvalidStamp(t *testing.T) {
	client := newTestClient(nil)
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	_, err := client.DialContext(ctx, "sdns://AQIAAAAAAAAAFDE")
	require.NotNil(t, err)
}

func TestTimeoutOnDialError(t *testing.T) {
	// AdGuard DNS pointing to a wrong IP.
	stampStr := "sdns://AQIAAAAAAAAADDguOC44Ljg6NTQ0MyDRK0fyUtzywrv4mRCG6vec5EldixbIoMQyLlLKPzkIcyIyLmRuc2NyeXB0LmRlZmF1bHQubnMxLmFkZ3VhcmQuY29t"

	client := newTestClient(nil)
	ctx := testutil.ContextWithTimeout(t, 300*time.Millisecond)
	_, err := client.DialContext(ctx, stampStr)
	require.NotNil(t, err)
	require.True(t, os.IsTimeout(err))
}

func TestTimeoutOnDialExchange(t *testing.T) {
	// AdGuard DNS.
	stampStr := "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
	client := newTestClient(nil)

	ctx := testutil.ContextWithTimeout(t, 300*time.Millisecond)
	serverInfo, err := client.DialContext(ctx, stampStr)
	require.NoError(t, err)

	serverInfo.ServerAddress = "8.8.8.8:5443"
	req := createTestMessage()

	_, err = client.ExchangeContext(ctx, req, serverInfo)

	require.NotNil(t, err)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
}

func TestFetchCertPublicResolvers(t *testing.T) {
	testCases := []struct {
		name     string
		stampStr string
	}{{
		name:     "AdGuard DNS",
		stampStr: "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
	}, {
		name:     "AdGuard DNS Family",
		stampStr: "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNTo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ",
	}, {
		name:     "AdGuard DNS Unfiltered",
		stampStr: "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNTo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ",
	}, {
		name:     "Cisco OpenDNS",
		stampStr: "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
	}, {
		name:     "Cisco OpenDNS Family Shield",
		stampStr: "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMTIzILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
	}, {
		name:     "Quad9",
		stampStr: "sdns://AQYAAAAAAAAAEzE0OS4xMTIuMTEyLjEwOjg0NDMgZ8hHuMh1jNEgJFVDvnVnRt803x2EwAuMRwNo34Idhj4ZMi5kbnNjcnlwdC1jZXJ0LnF1YWQ5Lm5ldA",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stamp, err := dnsstamps.NewServerStampFromString(tc.stampStr)
			require.NoError(t, err)

			c := newTestClient(&ClientConfig{
				Proto: ProtoUDP,
			})
			ctx := testutil.ContextWithTimeout(t, testTimeout)
			resolverInfo, err := c.DialStampContext(ctx, stamp)
			require.NoError(t, err)
			require.NotNil(t, resolverInfo)
			require.True(t, resolverInfo.ResolverCert.VerifyDate())
			require.True(t, resolverInfo.ResolverCert.VerifySignature(stamp.ServerPk))
		})
	}
}

func TestExchangePublicResolvers(t *testing.T) {
	testCases := []struct {
		name     string
		stampStr string
	}{{
		name:     "adguard_dns",
		stampStr: "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
	}, {
		name:     "adguard_dns_family",
		stampStr: "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNTo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ",
	}, {
		name:     "adguard_dns_unfiltered",
		stampStr: "sdns://AQMAAAAAAAAAEjk0LjE0MC4xNC4xNDA6NTQ0MyC16ETWuDo-PhJo62gfvqcN48X6aNvWiBQdvy7AZrLa-iUyLmRuc2NyeXB0LnVuZmlsdGVyZWQubnMxLmFkZ3VhcmQuY29t",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			checkDNSCryptServer(t, tc.stampStr, ProtoUDP)
			checkDNSCryptServer(t, tc.stampStr, ProtoTCP)
		})
	}
}

// chechDNSCryptServer is a helper that sends a test DNS request to the given
// server using the given protocol and verifies the result.
func checkDNSCryptServer(tb testing.TB, stampStr string, proto Proto) {
	tb.Helper()

	client := newTestClient(&ClientConfig{Proto: proto})
	ctx := testutil.ContextWithTimeout(tb, testTimeout)
	resolverInfo, err := client.DialContext(ctx, stampStr)
	require.NoError(tb, err)

	req := createTestMessage()

	reply, err := client.ExchangeContext(ctx, req, resolverInfo)
	require.NoError(tb, err)
	assertTestMessageResponse(tb, reply)
}

// createTestMessage is a helper that returns DNS message with default
// parameters.
func createTestMessage() (msg *dns.Msg) {
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: "google-public-dns-a.google.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	return &req
}

// assertTestMessageResponse verifies that the reply matches the default
// expectations.
func assertTestMessageResponse(tb testing.TB, reply *dns.Msg) {
	tb.Helper()

	require.NotNil(tb, reply)
	require.Equal(tb, 1, len(reply.Answer))
	a, ok := reply.Answer[0].(*dns.A)
	require.True(tb, ok)
	require.Equal(tb, net.IPv4(8, 8, 8, 8).To4(), a.A.To4())
}
