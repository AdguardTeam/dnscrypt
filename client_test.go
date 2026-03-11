package dnscrypt

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestParseStamp(t *testing.T) {
	stampStr := "sdns://AgUAAAAAAAAAAAAOZG5zLmdvb2dsZS5jb20NL2V4cGVyaW1lbnRhbA"
	stamp, err := dnsstamps.NewServerStampFromString(stampStr)

	if err != nil || stamp.ProviderName == "" {
		t.Fatalf("Could not parse stamp %s: %s", stampStr, err)
	}

	require.Equal(t, stampStr, stamp.String())
	require.Equal(t, dnsstamps.StampProtoTypeDoH, stamp.Proto)
	require.Equal(t, "dns.google.com", stamp.ProviderName)
	require.Equal(t, "/experimental", stamp.Path)

	stampStr = "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
	stamp, err = dnsstamps.NewServerStampFromString(stampStr)

	if err != nil || stamp.ProviderName == "" {
		t.Fatalf("Could not parse stamp %s: %s", stampStr, err)
	}

	require.Equal(t, stampStr, stamp.String())
	require.Equal(t, dnsstamps.StampProtoTypeDNSCrypt, stamp.Proto)
	require.Equal(t, "2.dnscrypt.default.ns1.adguard.com", stamp.ProviderName)
	require.Equal(t, "", stamp.Path)
	require.Equal(t, "94.140.14.14:5443", stamp.ServerAddrStr)
	require.Equal(t, keySize, len(stamp.ServerPk))
}

func TestInvalidStamp(t *testing.T) {
	client := Client{}
	_, err := client.Dial("sdns://AQIAAAAAAAAAFDE")
	require.NotNil(t, err)
}

func TestTimeoutOnDialError(t *testing.T) {
	// AdGuard DNS pointing to a wrong IP.
	stampStr := "sdns://AQIAAAAAAAAADDguOC44Ljg6NTQ0MyDRK0fyUtzywrv4mRCG6vec5EldixbIoMQyLlLKPzkIcyIyLmRuc2NyeXB0LmRlZmF1bHQubnMxLmFkZ3VhcmQuY29t"
	client := Client{Timeout: 300 * time.Millisecond}

	_, err := client.Dial(stampStr)
	require.NotNil(t, err)
	require.True(t, os.IsTimeout(err))
}

func TestTimeoutOnDialExchange(t *testing.T) {
	// AdGuard DNS.
	stampStr := "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
	client := Client{Timeout: 300 * time.Millisecond}

	serverInfo, err := client.Dial(stampStr)
	require.NoError(t, err)

	serverInfo.ServerAddress = "8.8.8.8:5443"
	req := createTestMessage()

	_, err = client.Exchange(req, serverInfo)

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

			c := &Client{
				Proto:   ProtoUDP,
				Timeout: time.Second * 5,
			}
			resolverInfo, err := c.DialStamp(stamp)
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

	client := Client{Proto: proto, Timeout: 10 * time.Second}
	resolverInfo, err := client.Dial(stampStr)
	require.NoError(tb, err)

	req := createTestMessage()

	reply, err := client.Exchange(req, resolverInfo)
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
