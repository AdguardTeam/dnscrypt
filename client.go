package dnscrypt

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
)

// Client is a DNSCrypt resolver client.
type Client struct {
	// Logger is a logger instance for Client.  If not set, slog.Default()
	// will be used.
	Logger *slog.Logger

	// Proto is the base network protocol.
	Proto Proto

	// Timeout is the read/write timeout.
	Timeout time.Duration

	// UDPSize is the maximum size of a DNS response (or query) this client
	// can send or receive.  If not set, we use dns.MinMsgSize by default.
	UDPSize int
}

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
	SharedKey [keySize]byte

	// SecretKey is the client short-term secret key.
	SecretKey [keySize]byte

	// PublicKey is the client short-term public key.
	PublicKey [keySize]byte
}

// Dial fetches and validates DNSCrypt certificate from the given server.
// Data received during this call is then used for DNS requests
// encryption/decryption.  stampStr is an sdns:// address which is parsed using
// go-dnsstamps package.
func (c *Client) Dial(stampStr string) (info *ResolverInfo, err error) {
	stamp, err := dnsstamps.NewServerStampFromString(stampStr)
	if err != nil {
		// Invalid SDNS stamp.
		return nil, err
	}

	if stamp.Proto != dnsstamps.StampProtoTypeDNSCrypt {
		return nil, ErrInvalidDNSStamp
	}

	return c.DialStamp(stamp)
}

// DialStamp fetches and validates DNSCrypt certificate from the given server.
// Data received during this call is then used for DNS requests
// encryption/decryption.
func (c *Client) DialStamp(stamp dnsstamps.ServerStamp) (info *ResolverInfo, err error) {
	info = &ResolverInfo{}

	// Generate the secret/public pair.
	info.SecretKey, info.PublicKey = generateRandomKeyPair()

	// Set the provider properties.
	info.ServerPublicKey = stamp.ServerPk
	info.ServerAddress = stamp.ServerAddrStr
	info.ProviderName = stamp.ProviderName

	cert, err := c.fetchCert(stamp)
	if err != nil {
		return nil, err
	}

	info.ResolverCert = cert

	// Compute shared key that we'll use to encrypt/decrypt messages.
	sharedKey, err := computeSharedKey(cert.EsVersion, &info.SecretKey, &cert.ResolverPk)
	if err != nil {
		return nil, err
	}

	info.SharedKey = sharedKey

	return info, nil
}

// Exchange performs a synchronous DNS query to the specified DNSCrypt server
// and returns a DNS response.  This method creates a new network connection
// for every call so avoid using it for TCP.  DNSCrypt cert needs to be
// fetched and validated prior to this call using the [Client.DialStamp] method.
// m and info must not be nil.
func (c *Client) Exchange(m *dns.Msg, info *ResolverInfo) (resp *dns.Msg, err error) {
	proto := ProtoUDP
	if c.Proto == ProtoTCP {
		proto = ProtoTCP
	}

	conn, err := net.Dial(string(proto), info.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("dialing: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, conn.Close()) }()

	resp, err = c.ExchangeConn(conn, m, info)
	if err != nil {
		return nil, fmt.Errorf("exchanging: %w", err)
	}

	return resp, nil
}

// ExchangeConn performs a synchronous DNS query to the specified DNSCrypt
// server and returns a DNS response.  DNSCrypt server information needs to be
// fetched and validated prior to this call using the [Client.DialStamp] method.
// conn, m, and info must not be nil.
func (c *Client) ExchangeConn(
	conn net.Conn,
	m *dns.Msg,
	info *ResolverInfo,
) (resp *dns.Msg, err error) {
	query, err := c.encrypt(m, info)
	if err != nil {
		return nil, err
	}

	err = c.writeQuery(conn, query)
	if err != nil {
		return nil, err
	}

	b, err := c.readResponse(conn)
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
func (c *Client) writeQuery(conn net.Conn, query []byte) (err error) {
	if c.Timeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(c.Timeout))
	}

	// Write to the connection.
	if _, ok := conn.(*net.TCPConn); ok {
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
func (c *Client) readResponse(conn net.Conn) (resp []byte, err error) {
	if c.Timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(c.Timeout))
	}

	proto := ProtoUDP
	if _, ok := conn.(*net.TCPConn); ok {
		proto = ProtoTCP
	}

	if proto == ProtoUDP {
		bufSize := c.UDPSize
		if bufSize == 0 {
			bufSize = dns.MinMsgSize
		}

		resp = make([]byte, bufSize)
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

	msg = new(dns.Msg)
	err = msg.Unpack(response)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// fetchCert loads DNSCrypt cert from the specified server.
func (c *Client) fetchCert(stamp dnsstamps.ServerStamp) (cert *Cert, err error) {
	providerName := stamp.ProviderName
	if !strings.HasSuffix(providerName, ".") {
		providerName = providerName + "."
	}

	query := new(dns.Msg)
	query.SetQuestion(providerName, dns.TypeTXT)
	// use 1252 as a UDPSize for this client to make sure the buffer is not too
	// small.
	client := dns.Client{Net: string(c.Proto), UDPSize: uint16(1252), Timeout: c.Timeout}
	r, _, err := client.Exchange(query, stamp.ServerAddrStr)
	if err != nil {
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

		cert, err = c.parseCert(stamp, currentCert, providerName, strings.Join(txt.Txt, ""))
		if err != nil {
			c.logger().Debug("bad cert", "provider", providerName, slogutil.KeyError, err)

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
	stamp dnsstamps.ServerStamp,
	currentCert *Cert,
	providerName string,
	certStr string,
) (cert *Cert, err error) {
	certBytes := unpackTxtString(certStr)

	cert = &Cert{}
	err = cert.Deserialize(certBytes)
	if err != nil {
		return nil, fmt.Errorf("deserializing cert for: %w", err)
	}

	c.logger().Debug(
		"fetched certificate",
		"provider",
		providerName,
		"cert_serial",
		cert.Serial,
	)

	if !cert.VerifyDate() {
		return nil, ErrInvalidDate
	}

	if !cert.VerifySignature(stamp.ServerPk) {
		return nil, ErrInvalidCertSignature
	}

	if cert.Serial < currentCert.Serial {
		c.logger().Debug(
			"cert superseded by a previous certificate",
			"provider",
			providerName,
			"cert_serial",
			cert.Serial,
		)

		return nil, nil
	}

	if cert.Serial > currentCert.Serial {
		return cert, nil
	}

	if cert.EsVersion <= currentCert.EsVersion {
		c.logger().Debug(
			"keeping the current cert es version",
			"provider",
			providerName,
		)

		return nil, nil
	}

	c.logger().Debug(
		"upgrading the construction",
		"provider",
		providerName,
		"es_version",
		currentCert.EsVersion,
		"new_es_version",
		cert.EsVersion,
	)

	return cert, nil
}

// maxQuerySize returns the maximum query size for the client.
func (c *Client) maxQuerySize() (size int) {
	if c.Proto == ProtoTCP {
		return dns.MaxMsgSize
	}

	if c.UDPSize > 0 {
		return c.UDPSize
	}

	return dns.MinMsgSize
}

// logger returns the logger instance or slog.Default() if it was not
// configured.
func (c *Client) logger() (l *slog.Logger) {
	if c.Logger == nil {
		return slog.Default()
	}

	return c.Logger
}
