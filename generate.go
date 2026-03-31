package dnscrypt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/ameshkov/dnsstamps"
	"golang.org/x/crypto/curve25519"
)

const (
	// DNSCryptV2Prefix is the prefix for DNSCrypt v2 provider names.
	DNSCryptV2Prefix = "2.dnscrypt-cert."

	// defaultCertValidity is the standard validity period for a generated
	// certificate.
	defaultCertValidity = 365 * 24 * time.Hour
)

// ResolverConfig is the DNSCrypt resolver configuration.
type ResolverConfig struct {
	// ProviderName is the DNSCrypt provider name.
	ProviderName string `yaml:"provider_name"`

	// PublicKey is the DNSCrypt resolver public key.
	PublicKey string `yaml:"public_key"`

	// PrivateKey is the DNSCrypt resolver private key.  The main and only
	// purpose of this key is to sign the certificate.
	PrivateKey string `yaml:"private_key"`

	// ResolverSk is a hex-encoded short-term private key.  This key is used to
	// encrypt/decrypt DNS queries.  If not set, we'll generate a new random
	// ResolverSk and ResolverPk.
	ResolverSk string `yaml:"resolver_secret"`

	// ResolverPk is a hex-encoded short-term public key corresponding to
	// ResolverSk.  This key is used to encrypt/decrypt DNS queries.
	ResolverPk string `yaml:"resolver_public"`

	// ESVersion is the crypto to use in this resolver.
	ESVersion CryptoConstruction `yaml:"es_version"`

	// CertificateTTL is the time-to-live value for the certificate that is
	// generated using this ResolverConfig.  If not set, we'll use 1 year by
	// default.
	CertificateTTL time.Duration `yaml:"certificate_ttl"`
}

// type check
var _ validate.Interface = (*ResolverConfig)(nil)

// Validate implements the [validate.Interface] for *ResolverConfig.
func (rc *ResolverConfig) Validate() (err error) {
	var errs []error
	errs = append(errs, validate.NotEmpty("public_key", rc.PublicKey))
	errs = append(errs, validate.NotEmpty("private_key", rc.PrivateKey))
	errs = append(errs, validate.NotEmpty("resolver_secret", rc.ResolverSk))

	return errors.Join(errs...)
}

// NewCert generates a signed Certificate to be used by Server.
func (rc *ResolverConfig) NewCert() (cert *Certificate, err error) {
	notAfter := time.Now()
	if rc.CertificateTTL > 0 {
		notAfter = notAfter.Add(rc.CertificateTTL)
	} else {
		notAfter = notAfter.Add(defaultCertValidity)
	}

	cert = &Certificate{
		Serial:    uint32(time.Now().Unix()),
		NotAfter:  uint32(notAfter.Unix()),
		NotBefore: uint32(time.Now().Unix()),
		ESVersion: rc.ESVersion,
	}

	resolverPk, err := HexDecodeKey(rc.ResolverPk)
	if err != nil {
		return nil, fmt.Errorf("decoding public key: %w", err)
	}

	resolverSk, err := HexDecodeKey(rc.ResolverSk)
	if err != nil {
		return nil, fmt.Errorf("decoding secret key: %w", err)
	}

	if len(resolverPk) != KeySize || len(resolverSk) != KeySize {
		sk, pk := generateRandomKeyPair()
		resolverSk = sk[:]
		resolverPk = pk[:]
	}

	copy(cert.ResolverPk[:], resolverPk[:])
	copy(cert.ResolverSk[:], resolverSk)

	privateKey, err := HexDecodeKey(rc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decoding private key: %w", err)
	}

	cert.Sign(privateKey)

	return cert, nil
}

// CreateStamp generates a DNS stamp for this resolver.
func (rc *ResolverConfig) CreateStamp(addr string) (stamp dnsstamps.ServerStamp, err error) {
	stamp = dnsstamps.ServerStamp{
		ProviderName: rc.ProviderName,
		Proto:        dnsstamps.StampProtoTypeDNSCrypt,
	}

	serverPk, err := HexDecodeKey(rc.PublicKey)
	if err != nil {
		return stamp, fmt.Errorf("decoding key: %w", err)
	}

	stamp.ServerPk = serverPk
	stamp.ServerAddrStr = addr

	return stamp, nil
}

// GenerateResolverConfig generates resolver configuration for a given provider
// name.  providerName is mandatory.  If needed, [DNSCryptV2Prefix] prefix is
// added to it.  privateKey is optional.  If not set, it will be generated
// automatically.
func GenerateResolverConfig(
	providerName string,
	privateKey ed25519.PrivateKey,
) (rc ResolverConfig, err error) {
	rc = ResolverConfig{
		ESVersion: XSalsa20Poly1305,
	}
	if !strings.HasPrefix(providerName, DNSCryptV2Prefix) {
		providerName = DNSCryptV2Prefix + providerName
	}

	rc.ProviderName = providerName

	if privateKey == nil {
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return rc, fmt.Errorf("generating key: %w", err)
		}
	}

	rc.PrivateKey = HexEncodeKey(privateKey)
	rc.PublicKey = HexEncodeKey(privateKey.Public().(ed25519.PublicKey))

	resolverSk, resolverPk := generateRandomKeyPair()
	rc.ResolverSk = HexEncodeKey(resolverSk[:])
	rc.ResolverPk = HexEncodeKey(resolverPk[:])

	return rc, nil
}

// HexEncodeKey encodes a byte slice to a hex-encoded string.
func HexEncodeKey(b []byte) (encoded string) {
	return strings.ToUpper(hex.EncodeToString(b))
}

// HexDecodeKey decodes a hex-encoded string with (optional) colons to a byte
// array.
func HexDecodeKey(str string) (decoded []byte, err error) {
	return hex.DecodeString(strings.ReplaceAll(str, ":", ""))
}

// generateRandomKeyPair generates a random key-pair.
func generateRandomKeyPair() (privateKey, publicKey [KeySize]byte) {
	privateKey = [KeySize]byte{}
	publicKey = [KeySize]byte{}

	_, _ = rand.Read(privateKey[:])
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return privateKey, publicKey
}
