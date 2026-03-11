package dnscrypt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/ameshkov/dnsstamps"
	"golang.org/x/crypto/curve25519"
)

const (
	// dnsCryptV2Prefix is the prefix for DNSCrypt v2 provider names.
	dnsCryptV2Prefix = "2.dnscrypt-cert."

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

	// EsVersion is the crypto to use in this resolver.
	EsVersion CryptoConstruction `yaml:"es_version"`

	// CertificateTTL is the time-to-live value for the certificate that is
	// generated using this ResolverConfig.  If not set, we'll use 1 year by
	// default.
	CertificateTTL time.Duration `yaml:"certificate_ttl"`
}

// CreateCert generates a signed Cert to be used by Server.
func (rc *ResolverConfig) CreateCert() (cert *Cert, err error) {
	notAfter := time.Now()
	if rc.CertificateTTL > 0 {
		notAfter = notAfter.Add(rc.CertificateTTL)
	} else {
		notAfter = notAfter.Add(defaultCertValidity)
	}

	cert = &Cert{
		Serial:    uint32(time.Now().Unix()),
		NotAfter:  uint32(notAfter.Unix()),
		NotBefore: uint32(time.Now().Unix()),
		EsVersion: rc.EsVersion,
	}

	resolverPk, err := HexDecodeKey(rc.ResolverPk)
	if err != nil {
		return nil, err
	}

	resolverSk, err := HexDecodeKey(rc.ResolverSk)
	if err != nil {
		return nil, err
	}

	if len(resolverPk) != keySize || len(resolverSk) != keySize {
		sk, pk := generateRandomKeyPair()
		resolverSk = sk[:]
		resolverPk = pk[:]
	}

	copy(cert.ResolverPk[:], resolverPk[:])
	copy(cert.ResolverSk[:], resolverSk)

	privateKey, err := HexDecodeKey(rc.PrivateKey)
	if err != nil {
		return nil, err
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
		return stamp, err
	}

	stamp.ServerPk = serverPk
	stamp.ServerAddrStr = addr

	return stamp, nil
}

// GenerateResolverConfig generates resolver configuration for a given provider
// name.  providerName is mandatory.  If needed, "2.dnscrypt-cert." prefix is
// added to it.  privateKey is optional.  If not set, it will be generated
// automatically.
func GenerateResolverConfig(
	providerName string,
	privateKey ed25519.PrivateKey,
) (rc ResolverConfig, err error) {
	rc = ResolverConfig{
		EsVersion: XSalsa20Poly1305,
	}
	if !strings.HasPrefix(providerName, dnsCryptV2Prefix) {
		providerName = dnsCryptV2Prefix + providerName
	}

	rc.ProviderName = providerName

	if privateKey == nil {
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return rc, err
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
func generateRandomKeyPair() (privateKey, publicKey [keySize]byte) {
	privateKey = [keySize]byte{}
	publicKey = [keySize]byte{}

	_, _ = rand.Read(privateKey[:])
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return privateKey, publicKey
}
