package dnscrypt

import (
	"cmp"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// testTimeout is a common timeout for tests.
const testTimeout = time.Second

// certToTXT is a helper that returns the string representation of a certificate
// wrapped inside a DNS TXT record.
func certToTXT(tb testing.TB, cert *Certificate) (txt *dns.TXT) {
	tb.Helper()

	b, _ := cert.MarshalBinary()

	return &dns.TXT{Txt: []string{packTxtString(b)}}
}

// newTestCertStr is a helper that creates a new certificate using the values in
// defaultCert as defaults and signs it.
func newTestCert(tb testing.TB, sk ed25519.PrivateKey, defaultCert, newCert *Certificate) (c *Certificate) {
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

func TestClient_ParseAnswer(t *testing.T) {
	t.Parallel()

	fqdn := "example.org."

	validCert, validPk, validSk := generateValidCert(t)
	_, wrongPk, wrongSk := generateValidCert(t)
	client := NewClient(&ClientConfig{})

	testCases := []struct {
		wantCert *Certificate
		name     string
		answer   []dns.RR
		serverPk ed25519.PublicKey
	}{{
		name: "invalid_cert_data",
		answer: []dns.RR{
			&dns.TXT{Txt: []string{"invalid", "cert"}},
		},
		serverPk: nil,
		wantCert: &Certificate{},
	}, {
		name: "mx_answer",
		answer: []dns.RR{
			&dns.MX{},
		},
		serverPk: nil,
		wantCert: &Certificate{},
	}, {
		name: "expired_cert",
		answer: []dns.RR{
			certToTXT(t, newTestCert(t, validSk, validCert, &Certificate{
				NotBefore: 1,
				NotAfter:  2,
			})),
		},
		serverPk: validPk,
		wantCert: &Certificate{},
	}, {
		name: "invalid_signature",
		answer: []dns.RR{
			certToTXT(t, newTestCert(t, wrongSk, validCert, nil)),
		},
		serverPk: validPk,
		wantCert: &Certificate{},
	}, {
		name: "wrong_public_key",
		answer: []dns.RR{
			certToTXT(t, newTestCert(t, validSk, validCert, nil)),
		},
		serverPk: wrongPk,
		wantCert: &Certificate{},
	}, {
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

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			cert := client.parseAnswer(ctx, tc.answer, tc.serverPk, fqdn)
			assert.Equal(t, tc.wantCert, cert)
		})
	}
}
