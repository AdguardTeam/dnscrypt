package dnscrypt

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/AdguardTeam/dnscrypt/internal/dnscrypttest"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTXTHdr is a common TXT DNS record header for tests.
var testTXTHdr = dns.RR_Header{
	Name:   dnscrypttest.FQDN,
	Rrtype: dns.TypeTXT,
	Class:  dns.ClassINET,
	Ttl:    uint32(dnscrypttest.TTL.Seconds()),
}

// certToTXT is a helper that returns the string representation of a certificate
// wrapped inside a DNS TXT record.
func certToTXT(tb testing.TB, cert *Certificate) (txt *dns.TXT) {
	tb.Helper()

	b, _ := cert.MarshalBinary()

	return &dns.TXT{Hdr: testTXTHdr, Txt: []string{packTxtString(b)}}
}

// newTestCertStr is a helper that creates a new certificate using the values in
// defaultCert as defaults and signs it.
func newTestCert(
	tb testing.TB,
	sk ed25519.PrivateKey,
	defaultCert *Certificate,
	newCert *Certificate,
) (c *Certificate) {
	tb.Helper()

	newCert = cmp.Or(newCert, defaultCert)
	newCert.Serial = cmp.Or(newCert.Serial, defaultCert.Serial)
	newCert.ESVersion = cmp.Or(newCert.ESVersion, defaultCert.ESVersion)
	newCert.ResolverPk = cmp.Or(newCert.ResolverPk, defaultCert.ResolverPk)
	newCert.ClientMagic = cmp.Or(newCert.ClientMagic, defaultCert.ClientMagic)
	newCert.NotBefore = cmp.Or(newCert.NotBefore, defaultCert.NotBefore)
	newCert.NotAfter = cmp.Or(newCert.NotAfter, defaultCert.NotAfter)

	newCert.Sign(sk)

	return newCert
}

func TestClient_FetchCert(t *testing.T) {
	t.Parallel()

	validCert, validPk, validSk := generateValidCert(t)
	client := NewClient(&ClientConfig{})

	testCases := []struct {
		wantCert *Certificate
		name     string
		answer   []dns.RR
		serverPk ed25519.PublicKey
	}{{
		name: "valid_cert",
		answer: []dns.RR{
			certToTXT(t, newTestCert(t, validSk, validCert, nil)),
		},
		serverPk: validPk,
		wantCert: newTestCert(t, validSk, validCert, &Certificate{
			ResolverPk: validCert.ResolverPk,
		}),
	}, {
		name: "higher_serial_after",
		answer: []dns.RR{
			certToTXT(t, newTestCert(t, validSk, validCert, nil)),
			certToTXT(t, newTestCert(t, validSk, validCert, &Certificate{
				Serial: validCert.Serial + 1,
			})),
		},
		serverPk: validPk,
		wantCert: newTestCert(t, validSk, validCert, &Certificate{
			Serial: validCert.Serial + 1,
		}),
	}, {
		name: "higher_serial_before",
		answer: []dns.RR{
			certToTXT(t, newTestCert(t, validSk, validCert, &Certificate{
				Serial: validCert.Serial + 1,
			})),
			certToTXT(t, newTestCert(t, validSk, validCert, nil)),
		},
		serverPk: validPk,
		wantCert: newTestCert(t, validSk, validCert, &Certificate{
			Serial: validCert.Serial + 1,
		}),
	}, {
		name: "same_serial_higher_es",
		answer: []dns.RR{
			certToTXT(t, newTestCert(t, validSk, validCert, &Certificate{
				ESVersion: XSalsa20Poly1305,
			})),
			certToTXT(t, newTestCert(t, validSk, validCert, &Certificate{
				ESVersion: XChacha20Poly1305,
			})),
		},
		serverPk: validPk,
		wantCert: newTestCert(t, validSk, validCert, &Certificate{
			ESVersion: XChacha20Poly1305,
		}),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := runTestDNSServer(t, tc.answer, dns.RcodeSuccess)

			ctx := testutil.ContextWithTimeout(t, dnscrypttest.Timeout)
			cert, err := client.fetchCert(ctx, dnsstamps.ServerStamp{
				ServerAddrStr: addr.String(),
				ProviderName:  dnscrypttest.FQDN,
				ServerPk:      tc.serverPk,
			})
			require.NoError(t, err)

			assert.Equal(t, tc.wantCert, cert)
		})
	}
}

func TestClient_FetchCert_fail(t *testing.T) {
	t.Parallel()

	validCert, validPk, validSk := generateValidCert(t)
	_, wrongPk, wrongSk := generateValidCert(t)
	client := NewClient(&ClientConfig{})

	noRRErrMsg := `no valid txt records for provider "` + dnscrypttest.FQDN + `"`

	testCases := []struct {
		name       string
		wantErrMsg string
		serverPk   ed25519.PublicKey
		answer     []dns.RR
		rcode      int
	}{{
		name: "invalid_cert_data",
		answer: []dns.RR{
			&dns.TXT{Hdr: testTXTHdr, Txt: []string{"invalid", "cert"}},
		},
		serverPk:   nil,
		wantErrMsg: noRRErrMsg,
		rcode:      dns.RcodeSuccess,
	}, {
		name: "mx_answer",
		answer: []dns.RR{
			&dns.MX{Hdr: dns.RR_Header{
				Name:   dnscrypttest.FQDN,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    uint32(dnscrypttest.TTL.Seconds()),
			}},
		},
		serverPk:   nil,
		wantErrMsg: noRRErrMsg,
		rcode:      dns.RcodeSuccess,
	}, {
		name: "expired_cert",
		answer: []dns.RR{
			certToTXT(t, newTestCert(t, validSk, validCert, &Certificate{
				NotBefore: 1,
				NotAfter:  2,
			})),
		},
		serverPk:   validPk,
		wantErrMsg: noRRErrMsg,
		rcode:      dns.RcodeSuccess,
	}, {
		name:       "rcode_refused",
		answer:     nil,
		serverPk:   validPk,
		wantErrMsg: ErrFailedToFetchCert.Error(),
		rcode:      dns.RcodeRefused,
	}, {
		name: "invalid_signature",
		answer: []dns.RR{
			certToTXT(t, newTestCert(t, wrongSk, validCert, nil)),
		},
		serverPk:   validPk,
		wantErrMsg: noRRErrMsg,
		rcode:      dns.RcodeSuccess,
	}, {
		name: "wrong_public_key",
		answer: []dns.RR{
			certToTXT(t, newTestCert(t, validSk, validCert, nil)),
		},
		serverPk:   wrongPk,
		wantErrMsg: noRRErrMsg,
		rcode:      dns.RcodeSuccess,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			addr := runTestDNSServer(t, tc.answer, tc.rcode)

			ctx := testutil.ContextWithTimeout(t, dnscrypttest.Timeout)
			cert, err := client.fetchCert(ctx, dnsstamps.ServerStamp{
				ServerAddrStr: addr.String(),
				ProviderName:  dnscrypttest.FQDN,
				ServerPk:      tc.serverPk,
			})
			assert.Nil(t, cert)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

// runTestDNSServer is a helper that runs a DNS server that serves requests with
// given data using the UDP protocol.
func runTestDNSServer(tb testing.TB, answ []dns.RR, rcode int) (addr net.Addr) {
	tb.Helper()

	ready := make(chan struct{})

	s := &dns.Server{
		Addr: netip.AddrPortFrom(netutil.IPv4Localhost(), 0).String(),
		Net:  string(ProtoUDP),
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			pt := testutil.NewPanicT(tb)

			msg := &dns.Msg{}
			msg.SetReply(r)
			msg.Answer = slices.Clone(answ)
			msg.Rcode = rcode

			err := w.WriteMsg(msg)
			require.NoError(pt, err)
		}),
	}

	s.NotifyStartedFunc = func() {
		addr = s.PacketConn.LocalAddr()
		close(ready)
	}

	go func() {
		pt := testutil.NewPanicT(tb)
		err := s.ListenAndServe()
		require.NoError(pt, err)
	}()

	testutil.CleanupAndRequireSuccess(tb, s.Shutdown)
	testutil.RequireReceive(tb, ready, dnscrypttest.Timeout)

	return addr
}

// TODO(f.setrakov): Consider moving to external tests.
func TestClient_ExchangeContext_validateNonce(t *testing.T) {
	t.Parallel()

	handler := HandlerFunc(func(ctx context.Context, rw ResponseWriter, m *dns.Msg) (err error) {
		pt := testutil.NewPanicT(t)
		tcpRw := testutil.RequireTypeAssert[*tcpResponseWriter](pt, rw)
		tcpRw.query.Nonce = nonce{}

		return rw.WriteMsg(ctx, m)
	})

	rc, err := GenerateResolverConfig(dnscrypttest.Hostname, nil, dnscrypttest.TTL)
	require.NoError(t, err)

	resolverPk, err := HexDecodeKey(rc.PublicKey)
	require.NoError(t, err)

	cert, err := rc.NewCert()
	require.NoError(t, err)

	s, err := NewServer(&ServerConfig{
		Logger:       dnscrypttest.Logger,
		ProviderName: rc.ProviderName,
		ResolverCert: cert,
		Handler:      handler,
		Addr:         netip.AddrPortFrom(netutil.IPv4Localhost(), 0),
		Proto:        ProtoTCP,
	})
	require.NoError(t, err)
	servicetest.RequireRun(t, s, dnscrypttest.Timeout)

	client := NewClient(&ClientConfig{
		Proto: ProtoTCP,
	})

	ctx := testutil.ContextWithTimeout(t, dnscrypttest.Timeout)
	info, err := client.DialContext(ctx, (&dnsstamps.ServerStamp{
		ServerPk:      resolverPk,
		ProviderName:  rc.ProviderName,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
		ServerAddrStr: s.LocalAddr().String(),
	}).String())
	require.NoError(t, err)

	msg := dnscrypttest.NewDNSMessage()

	wantErrMsg := "exchanging: decrypting response: decrypting server response: " +
		ErrUnexpectedNonce.Error()
	_, err = client.ExchangeContext(ctx, msg, info)
	testutil.AssertErrorMsg(t, wantErrMsg, err)
}
