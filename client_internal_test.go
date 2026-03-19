package dnscrypt

import (
	"cmp"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

// testTimeout is a common timeout for tests.
const testTimeout = time.Second

// certToString is a helper that returns the certificate string representation.
func certToString(tb testing.TB, cert *Cert) (s string) {
	tb.Helper()

	b, _ := cert.MarshalBinary()

	return packTxtString(b)
}

// newTestCertStr is a helper that creates a new certificate using the values in
// defaultCert as defaults and signs it.
func newTestCert(tb testing.TB, sk ed25519.PrivateKey, defaultCert, newCert *Cert) (c *Cert) {
	tb.Helper()

	newCert = cmp.Or(newCert, defaultCert)
	newCert.Serial = cmp.Or(newCert.Serial, defaultCert.Serial)
	newCert.EsVersion = cmp.Or(newCert.EsVersion, defaultCert.EsVersion)
	newCert.ResolverPk = cmp.Or(newCert.ResolverPk, defaultCert.ResolverPk)
	newCert.ClientMagic = cmp.Or(newCert.ClientMagic, defaultCert.ClientMagic)
	newCert.NotBefore = cmp.Or(newCert.NotBefore, defaultCert.NotBefore)
	newCert.NotAfter = cmp.Or(newCert.NotAfter, defaultCert.NotAfter)

	newCert.Sign(sk)

	return newCert
}

func TestClient_parseCert(t *testing.T) {
	t.Parallel()

	fqdn := "example.org."

	validCert, validPk, validSk := generateValidCert(t)
	_, wrongPk, wrongSk := generateValidCert(t)
	client := NewClient(&ClientConfig{})

	testCases := []struct {
		currentCert *Cert
		wantCert    *Cert
		name        string
		certStr     string
		wantErrMsg  string
		serverPk    ed25519.PublicKey
	}{{
		name:        "invalid_cert_data",
		serverPk:    validPk,
		currentCert: &Cert{},
		certStr:     "invalid",
		wantErrMsg:  "deserializing cert for: cert is too short",
	}, {
		name:        "expired_cert",
		serverPk:    validPk,
		currentCert: &Cert{},
		certStr: certToString(t, newTestCert(t, validSk, validCert, &Cert{
			NotBefore: 1,
			NotAfter:  2,
		})),
		wantErrMsg: ErrInvalidDate.Error(),
	}, {
		name:        "invalid_signature",
		serverPk:    validPk,
		currentCert: &Cert{},
		certStr:     certToString(t, newTestCert(t, wrongSk, validCert, nil)),
		wantErrMsg:  ErrInvalidCertSignature.Error(),
	}, {
		name:        "wrong_public_key",
		serverPk:    wrongPk,
		currentCert: &Cert{},
		certStr:     certToString(t, newTestCert(t, validSk, validCert, nil)),
		wantErrMsg:  ErrInvalidCertSignature.Error(),
	}, {
		name:        "valid_cert",
		serverPk:    validPk,
		currentCert: &Cert{},
		certStr:     certToString(t, newTestCert(t, validSk, validCert, nil)),
		wantCert: newTestCert(t, validSk, validCert, &Cert{
			ResolverPk: validCert.ResolverPk,
		}),
	}, {
		name:        "newer_serial",
		serverPk:    validPk,
		currentCert: validCert,
		certStr: certToString(t, newTestCert(t, validSk, validCert, &Cert{
			Serial: validCert.Serial + 1,
		})),
		wantCert: newTestCert(t, validSk, validCert, &Cert{
			Serial: validCert.Serial + 1,
		}),
	}, {
		name:        "older_serial",
		serverPk:    validPk,
		currentCert: &Cert{Serial: validCert.Serial + 1},
		certStr:     certToString(t, newTestCert(t, validSk, validCert, nil)),
	}, {
		name:        "same_serial_lower_es",
		serverPk:    validPk,
		currentCert: validCert,
		certStr: certToString(t, newTestCert(t, validSk, validCert, &Cert{
			EsVersion: XSalsa20Poly1305,
		})),
	}, {
		name:        "same_serial_same_es",
		serverPk:    validPk,
		currentCert: validCert,
		certStr:     certToString(t, newTestCert(t, validSk, validCert, nil)),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			cert, err := client.parseCert(ctx, tc.serverPk, tc.currentCert, fqdn, tc.certStr)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			assert.Equal(t, tc.wantCert, cert)
		})
	}
}
