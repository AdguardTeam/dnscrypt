package dnscrypt

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
)

// ResolverInfo contains DNSCrypt resolver information necessary for
// decryption/encryption.
type ResolverInfo struct {
	// ResolverCert contains certificate info (obtained with the first
	// unencrypted DNS request).
	ResolverCert *Cert

	// ServerAddress is the server IP address.
	ServerAddress string

	// ProviderName is the provider name.
	ProviderName string

	// ServerPublicKey is the resolver public key (this key is used to
	// validate cert signature).
	ServerPublicKey ed25519.PublicKey

	// SharedKey is the shared key that is to be used to encrypt/decrypt
	// messages.
	SharedKey [KeySize]byte

	// SecretKey is the client short-term secret key.
	SecretKey [KeySize]byte

	// PublicKey is the client short-term public key.
	PublicKey [KeySize]byte
}

// ClientConfig is the configuration structure for [Client].
type ClientConfig struct {
	// Logger is a logger instance for Client.  If not set, slog.Default()
	// will be used.
	Logger *slog.Logger

	// Proto is the base network protocol.
	Proto Proto

	// UDPSize is the maximum size of a DNS response (or query) this client
	// can send or receive.  If not set, we use [dns.MinMsgSize] by default.
	UDPSize int
}

// Client is a DNSCrypt resolver client.
type Client struct {
	logger  *slog.Logger
	dialer  *net.Dialer
	proto   Proto
	udpSize int
}

// NewClient returns properly initialized *Client.  c must be non-nil and valid.
func NewClient(conf *ClientConfig) (c *Client) {
	return &Client{
		logger:  cmp.Or(conf.Logger, slog.Default()),
		dialer:  &net.Dialer{},
		proto:   conf.Proto,
		udpSize: cmp.Or(conf.UDPSize, dns.MinMsgSize),
	}
}

// DialContext fetches and validates DNSCrypt certificate from the given server.
// Data received during this call is then used for DNS requests
// encryption/decryption.  stampStr is an sdns:// address which is parsed using
// go-dnsstamps package.
func (c *Client) DialContext(ctx context.Context, stampStr string) (info *ResolverInfo, err error) {
	stamp, err := dnsstamps.NewServerStampFromString(stampStr)
	if err != nil {
		// Invalid SDNS stamp.
		return nil, err
	}

	if stamp.Proto != dnsstamps.StampProtoTypeDNSCrypt {
		return nil, ErrInvalidDNSStamp
	}

	return c.DialStampContext(ctx, stamp)
}

// DialStampContext fetches and validates DNSCrypt certificate from the given
// server.  Data received during this call is then used for DNS requests
// encryption/decryption.
func (c *Client) DialStampContext(
	ctx context.Context,
	stamp dnsstamps.ServerStamp,
) (info *ResolverInfo, err error) {
	info = &ResolverInfo{}
	info.SecretKey, info.PublicKey = generateRandomKeyPair()

	info.ServerPublicKey = stamp.ServerPk
	info.ServerAddress = stamp.ServerAddrStr
	info.ProviderName = stamp.ProviderName

	cert, err := c.fetchCert(ctx, stamp)
	if err != nil {
		return nil, err
	}

	info.ResolverCert = cert
	sharedKey, err := computeSharedKey(cert.EsVersion, &info.SecretKey, &cert.ResolverPk)
	if err != nil {
		return nil, err
	}

	info.SharedKey = sharedKey

	return info, nil
}

// ExchangeContext performs a synchronous DNS query to the specified DNSCrypt
// server and returns a DNS response.  This method creates a new network
// connection for every call so avoid using it for TCP.  DNSCrypt cert needs to
// be fetched and validated prior to this call using the
// [Client.DialStampContext] method.  m and info must not be nil.
func (c *Client) ExchangeContext(
	ctx context.Context,
	m *dns.Msg,
	info *ResolverInfo,
) (resp *dns.Msg, err error) {
	proto := ProtoUDP
	if c.proto == ProtoTCP {
		proto = ProtoTCP
	}

	conn, err := c.dialer.DialContext(ctx, string(proto), info.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("dialing: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, conn.Close()) }()

	resp, err = c.ExchangeConnContext(ctx, conn, m, info)
	if err != nil {
		return nil, fmt.Errorf("exchanging: %w", err)
	}

	return resp, nil
}

// ExchangeConnContext performs a synchronous DNS query to the specified
// DNSCrypt server and returns a DNS response.  DNSCrypt server information
// needs to be fetched and validated prior to this call using the
// [Client.DialStampContext] method.  conn, m, and info must not be nil.
func (c *Client) ExchangeConnContext(
	ctx context.Context,
	conn net.Conn,
	m *dns.Msg,
	info *ResolverInfo,
) (resp *dns.Msg, err error) {
	query, err := c.encrypt(m, info)
	if err != nil {
		return nil, err
	}

	err = c.writeQuery(ctx, conn, query)
	if err != nil {
		return nil, err
	}

	b, err := c.readResponse(ctx, conn)
	if err != nil {
		return nil, err
	}

	resp, err = c.decrypt(b, info)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// writeQuery writes query to the network connection.  Depending on the
// protocol we may write a 2-byte prefix or not.  conn must not be nil.
//
// TODO(f.setrakov): Improve error handling.
func (c *Client) writeQuery(ctx context.Context, conn net.Conn, query []byte) (err error) {
	deadline, ok := ctx.Deadline()
	if ok {
		_ = conn.SetWriteDeadline(deadline)
	}

	if _, ok = conn.(*net.TCPConn); ok {
		l := make([]byte, 2)
		binary.BigEndian.PutUint16(l, uint16(len(query)))
		_, err = (&net.Buffers{l, query}).WriteTo(conn)
	} else {
		_, err = conn.Write(query)
	}

	return err
}

// readResponse reads response from the network connection depending on the
// protocol, we may read a 2-byte prefix or not.  conn must not be nil.
//
// TODO(f.setrakov): Improve error handling.
func (c *Client) readResponse(ctx context.Context, conn net.Conn) (resp []byte, err error) {
	deadline, ok := ctx.Deadline()
	if ok {
		_ = conn.SetReadDeadline(deadline)
	}

	proto := ProtoUDP
	if _, ok = conn.(*net.TCPConn); ok {
		proto = ProtoTCP
	}

	if proto == ProtoUDP {
		resp = make([]byte, c.udpSize)
		var n int
		n, err = conn.Read(resp)
		if err != nil {
			return nil, err
		}

		return resp[:n], nil
	}

	// If we got here, this is a TCP connection so we should read a 2-byte
	// prefix first.
	return readPrefixed(conn)
}

// encrypt encrypts a DNS message using shared key from the resolver info.  m
// and info must not be nil.
func (c *Client) encrypt(m *dns.Msg, info *ResolverInfo) (msg []byte, err error) {
	q := EncryptedQuery{
		EsVersion:   info.ResolverCert.EsVersion,
		ClientMagic: info.ResolverCert.ClientMagic,
		ClientPk:    info.PublicKey,
	}
	query, err := m.Pack()
	if err != nil {
		return nil, err
	}

	msg, err = q.Encrypt(query, info.SharedKey)
	if len(msg) > c.maxQuerySize() {
		return nil, ErrQueryTooLarge
	}

	return msg, err
}

// decrypt decrypts a DNS message using a shared key from the resolver info.
// info must not be nil.
func (c *Client) decrypt(b []byte, info *ResolverInfo) (msg *dns.Msg, err error) {
	dr := EncryptedResponse{
		EsVersion: info.ResolverCert.EsVersion,
	}

	response, err := dr.Decrypt(b, info.SharedKey)
	if err != nil {
		return nil, err
	}

	msg = &dns.Msg{}
	err = msg.Unpack(response)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// fetchCert loads DNSCrypt cert from the specified server.
func (c *Client) fetchCert(
	ctx context.Context,
	stamp dnsstamps.ServerStamp,
) (cert *Cert, err error) {
	providerName := stamp.ProviderName
	if !strings.HasSuffix(providerName, ".") {
		providerName = providerName + "."
	}

	query := &dns.Msg{}
	query.SetQuestion(providerName, dns.TypeTXT)
	client := dns.Client{Net: string(c.proto), UDPSize: uint16(defaultUDPSize)}
	r, _, err := client.ExchangeContext(ctx, query, stamp.ServerAddrStr)
	if err != nil {
		// TODO(f.setrakov): Improve error wrapping.
		return nil, err
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, ErrFailedToFetchCert
	}

	currentCert := &Cert{}
	foundValid := false
	for _, rr := range r.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}

		certStr := strings.Join(txt.Txt, "")
		cert, err = c.parseCert(ctx, stamp.ServerPk, currentCert, providerName, certStr)
		if err != nil {
			c.logger.DebugContext(ctx,
				"bad cert",
				"provider", providerName,
				slogutil.KeyError, err,
			)

			continue
		} else if cert == nil {
			continue
		}

		currentCert = cert
		foundValid = true
	}

	if foundValid {
		return currentCert, nil
	} else if err == nil {
		err = fmt.Errorf("no valid txt records for provider %q", providerName)
	}

	return nil, err
}

// parseCert parses a certificate from its string form and returns it if it
// has priority over currentCert.  currentCert must not be nil.
func (c *Client) parseCert(
	ctx context.Context,
	serverPk ed25519.PublicKey,
	currentCert *Cert,
	providerName string,
	certStr string,
) (cert *Cert, err error) {
	certBytes := unpackTxtString(certStr)

	cert = &Cert{}
	err = cert.UnmarshalBinary(certBytes)
	if err != nil {
		return nil, fmt.Errorf("deserializing cert for: %w", err)
	}

	c.logger.DebugContext(
		ctx,
		"fetched certificate",
		"provider", providerName,
		"cert_serial", cert.Serial,
	)

	if !cert.VerifyDate() {
		return nil, ErrInvalidDate
	}

	if !cert.VerifySignature(serverPk) {
		return nil, ErrInvalidCertSignature
	}

	if cert.Serial < currentCert.Serial {
		c.logger.DebugContext(
			ctx,
			"cert superseded by a previous certificate",
			"provider", providerName,
			"cert_serial", cert.Serial,
		)

		return nil, nil
	}

	if cert.Serial > currentCert.Serial {
		return cert, nil
	}

	if cert.EsVersion <= currentCert.EsVersion {
		c.logger.DebugContext(
			ctx,
			"keeping the current cert es version",
			"provider", providerName,
		)

		return nil, nil
	}

	c.logger.DebugContext(
		ctx,
		"upgrading the construction",
		"provider", providerName,
		"es_version", currentCert.EsVersion,
		"new_es_version", cert.EsVersion,
	)

	return cert, nil
}

// maxQuerySize returns the maximum query size for the client.
func (c *Client) maxQuerySize() (size int) {
	if c.proto == ProtoTCP {
		return dns.MaxMsgSize
	}

	return c.udpSize
}
