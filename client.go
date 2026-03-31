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
	ResolverCert *Certificate

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
		return nil, fmt.Errorf("creating server stamp: %w", err)
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
		return nil, fmt.Errorf("fetching cert: %w", err)
	}

	info.ResolverCert = cert
	sharedKey, err := computeSharedKey(cert.ESVersion, &info.SecretKey, &cert.ResolverPk)
	if err != nil {
		return nil, fmt.Errorf("computing shared key: %w", err)
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
		return nil, fmt.Errorf("encrypting: %w", err)
	}

	err = c.writeQuery(ctx, conn, query)
	if err != nil {
		return nil, fmt.Errorf("writing query: %w", err)
	}

	b, err := c.readResponse(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	resp, err = c.decrypt(b, info)
	if err != nil {
		return nil, fmt.Errorf("decrypting response: %w", err)
	}

	return resp, nil
}

// writeQuery writes query to the network connection.  Depending on the
// protocol we may write a 2-byte prefix or not.  conn must not be nil.
func (c *Client) writeQuery(ctx context.Context, conn net.Conn, query []byte) (err error) {
	deadline, ok := ctx.Deadline()
	if ok {
		_ = conn.SetWriteDeadline(deadline)
	}

	if _, ok = conn.(*net.TCPConn); ok {
		l := make([]byte, 2)
		binary.BigEndian.PutUint16(l, uint16(len(query)))
		_, err = (&net.Buffers{l, query}).WriteTo(conn)
		if err != nil {
			return fmt.Errorf("writing to tcp connection: %w", err)
		}
	} else {
		_, err = conn.Write(query)
		if err != nil {
			return fmt.Errorf("writing to connection: %w", err)
		}
	}

	return nil
}

// readResponse reads response from the network connection depending on the
// protocol, we may read a 2-byte prefix or not.  conn must not be nil.
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
	q := &encryptedQuery{
		ESVersion:   info.ResolverCert.ESVersion,
		ClientMagic: info.ResolverCert.ClientMagic,
		ClientPk:    info.PublicKey,
	}
	query, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing dns message: %w", err)
	}

	msg, err = q.encrypt(query, info.SharedKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting message: %w", err)
	}

	if len(msg) > c.maxQuerySize() {
		return nil, ErrQueryTooLarge
	}

	return msg, nil
}

// decrypt decrypts a DNS message using a shared key from the resolver info.
// info must not be nil.
func (c *Client) decrypt(b []byte, info *ResolverInfo) (msg *dns.Msg, err error) {
	dr := &encryptedResponse{
		ESVersion: info.ResolverCert.ESVersion,
	}

	response, err := dr.decrypt(b, info.SharedKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting server response: %w", err)
	}

	msg = &dns.Msg{}
	err = msg.Unpack(response)
	if err != nil {
		return nil, fmt.Errorf("unpacking dns message: %w", err)
	}

	return msg, nil
}

// fetchCert loads DNSCrypt cert from the specified server.
func (c *Client) fetchCert(
	ctx context.Context,
	stamp dnsstamps.ServerStamp,
) (cert *Certificate, err error) {
	providerName := stamp.ProviderName
	if !strings.HasSuffix(providerName, ".") {
		providerName = providerName + "."
	}

	query := &dns.Msg{}
	query.SetQuestion(providerName, dns.TypeTXT)
	client := dns.Client{Net: string(c.proto), UDPSize: uint16(defaultUDPSize)}
	r, _, err := client.ExchangeContext(ctx, query, stamp.ServerAddrStr)
	if err != nil {
		return nil, fmt.Errorf("sending dns query: %w", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, ErrFailedToFetchCert
	}

	cert = c.parseAnswer(ctx, r.Answer, stamp.ServerPk, stamp.ProviderName)
	if cert == nil {
		return nil, fmt.Errorf("no valid txt records for provider %q", providerName)
	}

	return cert, nil
}

// parseAnswer parses DNS TXT records and returns the certificate with the
// highest priority.
func (c *Client) parseAnswer(
	ctx context.Context,
	answer []dns.RR,
	serverPk ed25519.PublicKey,
	providerName string,
) (cert *Certificate) {
	cert = &Certificate{}
	for _, rr := range answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}

		certStr := strings.Join(txt.Txt, "")

		currentCert := &Certificate{}
		err := currentCert.UnmarshalBinary(unpackTxtString(certStr))
		if err != nil {
			c.logger.DebugContext(
				ctx,
				"faield to parse certificate",
				"provider_name", providerName,
				slogutil.KeyError, err,
			)

			continue
		}

		err = verifyCert(currentCert, serverPk)
		if err != nil {
			c.logger.DebugContext(
				ctx,
				"failed to verify certificate",
				"provider_name", providerName,
				slogutil.KeyError, err,
			)

			continue
		}

		if c.certHasHigherPriority(ctx, cert, currentCert, providerName) {
			cert = currentCert
		}
	}

	return cert
}

// certHasHigherPriority returns true if current has higher priority than prev.
// A higher serial number is preferred, or a higher ESVersion if the serial
// numbers are the same.  prev and current must not be nil.
func (c *Client) certHasHigherPriority(
	ctx context.Context,
	prev *Certificate,
	current *Certificate,
	providerName string,
) (hasHigherPriority bool) {
	if prev.Serial > current.Serial {
		c.logger.DebugContext(
			ctx,
			"cert superseded by a previous certificate",
			"provider", providerName,
			"cert_serial", current.Serial,
		)

		return false
	}

	if prev.Serial < current.Serial {
		return true
	}

	if current.ESVersion <= prev.ESVersion {
		c.logger.DebugContext(
			ctx,
			"keeping the current cert es version",
			"provider", providerName,
		)

		return false
	}

	c.logger.DebugContext(
		ctx,
		"upgrading the construction",
		"provider", providerName,
		"es_version", prev.ESVersion,
		"new_es_version", current.ESVersion,
	)

	return true
}

// verifyCert verifies the date and signature of the certificate.  cert must not
// be nil.
//
// TODO(f.setrakov): Consider validating the date separately and use
// [Certificate.Validate].
func verifyCert(cert *Certificate, serverPk ed25519.PublicKey) (err error) {
	if !cert.VerifyDate() {
		return ErrInvalidDate
	}

	if !cert.VerifySignature(serverPk) {
		return ErrInvalidCertSignature
	}

	return nil
}

// maxQuerySize returns the maximum query size for the client.
func (c *Client) maxQuerySize() (size int) {
	if c.proto == ProtoTCP {
		return dns.MaxMsgSize
	}

	return c.udpSize
}
