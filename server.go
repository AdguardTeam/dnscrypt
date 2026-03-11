package dnscrypt

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
)

// defaultReadTimeout is the default read timeout for all reads.
const defaultReadTimeout = 2 * time.Second

// defaultTCPIdleTimeout is the timeout used for TCP connections after the first
// read.  For the first read [defaultReadTimeout] is used.
const defaultTCPIdleTimeout = 8 * time.Second

// defaultUDPSize is the default size of the UDP read buffer.  The release notes
// for dnscrypt-proxy version 1.1.0-RC1 claim that this size was chosen as the
// maximum one "for compatibility with some scary network setups", and making it
// smaller seems to break things for some people.
//
// See also: https://github.com/AdguardTeam/AdGuardDNS/issues/188.
const defaultUDPSize = 1252

// longTimeAgo is a helper variable that is used in several SetReadDeadline
// calls.
var longTimeAgo = time.Unix(1, 0)

// ServerDNSCrypt is an interface for a DNSCrypt server.
type ServerDNSCrypt interface {
	// ServeTCP listens to TCP connections, queries are then processed by
	// [Server.Handler].  It blocks the calling goroutine and to stop it you
	// need to close the listener or call [ServerDNSCrypt.Shutdown].
	ServeTCP(l net.Listener) error

	// ServeUDP listens to UDP connections, queries are then processed by
	// [Server.Handler].  It blocks the calling goroutine and to stop it you
	// need to close the listener or call [ServerDNSCrypt.Shutdown].
	ServeUDP(l *net.UDPConn) error

	// Shutdown tries to gracefully shutdown the server.  It waits until all
	// connections are processed and only after that it leaves the method.  If
	// context deadline is specified, it will exit earlier.
	Shutdown(ctx context.Context) error
}

// Server is the default implementation of the [ServerDNSCrypt] interface.
type Server struct {
	// Handler to invoke.  If nil, the [DefaultHandler] is used.
	Handler Handler

	// ResolverCert contains resolver certificate.  It must not be nil.
	ResolverCert *Cert

	// Logger is a logger instance for Server.  If not set, slog.Default() will
	// be used.
	Logger *slog.Logger

	// tcpListeners tracks active TCP listeners.
	tcpListeners map[net.Listener]struct{}

	// udpListeners tracks active UDP listeners.
	udpListeners map[*net.UDPConn]struct{}

	// tcpConns tracks active connections.
	//
	// TODO(f.setrakov): Consider using syncutil.Map.
	tcpConns map[net.Conn]struct{}

	// ProviderName is a DNSCrypt provider name.
	ProviderName string

	// wg tracks active workers (servers).
	wg sync.WaitGroup

	// UDPSize is the default buffer size to use to read incoming UDP messages.
	// If not set it defaults to defaultUDPSize (1252 B).
	UDPSize int

	// lock protects access to all the fields below.
	lock sync.RWMutex

	// initOnce makes sure init is called only once.
	initOnce sync.Once

	// started indicates whether the server is processing queries.
	started bool
}

// type check
var _ ServerDNSCrypt = (*Server)(nil)

// prepareShutdown prepares the server to shutdown: unblocks reads from all
// connections related to this server, marks the server as stopped.  If the
// server is not started, returns [ErrServerNotStarted].
func (s *Server) prepareShutdown() (err error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if !s.started {
		s.logger().Info("server is not started")

		return ErrServerNotStarted
	}

	s.started = false

	// These listeners were passed to us from the outside so we cannot close
	// them here - this is up to the calling code to do that.  Instead of that,
	// we call Set(Read)Deadline to unblock goroutines that are currently
	// blocked on reading from those listeners.  For tcpConns we would like to
	// avoid closing them to be able to process queries before shutting
	// everything down.
	for conn := range s.tcpConns {
		_ = conn.SetReadDeadline(longTimeAgo)
	}

	for l := range s.tcpListeners {
		switch v := l.(type) {
		case *net.TCPListener:
			_ = v.SetDeadline(longTimeAgo)
		}
	}

	for l := range s.udpListeners {
		_ = l.SetReadDeadline(longTimeAgo)
	}

	return nil
}

// Shutdown tries to gracefully shutdown the server.  It waits until all
// connections are processed and only after that it leaves the method.  If
// context deadline is specified, it will exit earlier.
func (s *Server) Shutdown(ctx context.Context) (err error) {
	s.logger().Info("shutting down the DNSCrypt server")

	err = s.prepareShutdown()
	if err != nil {
		return err
	}

	closed := make(chan struct{})
	go func() {
		s.wg.Wait()
		s.logger().Info("serve goroutines finished their work")
		close(closed)
	}()

	select {
	case <-closed:
		s.logger().Info("DNSCrypt server has been stopped")
	case <-ctx.Done():
		s.logger().Info("DNSCrypt server shutdown has timed out")
		err = ctx.Err()
	}

	return err
}

// init initializes (lazily) Server properties on startup.  This method is
// called from [Server.ServeTCP] and [Server.ServeUDP].
func (s *Server) init() {
	s.tcpConns = map[net.Conn]struct{}{}
	s.udpListeners = map[*net.UDPConn]struct{}{}
	s.tcpListeners = map[net.Listener]struct{}{}

	if s.UDPSize == 0 {
		s.UDPSize = defaultUDPSize
	}
}

// logger returns the logger instance or slog.Default() if it was not
// configured.
func (s *Server) logger() (l *slog.Logger) {
	if s.Logger == nil {
		return slog.Default()
	}

	return s.Logger
}

// isStarted returns true if the server is processing queries right now.  It
// means that [Server.ServeTCP] and/or [Server.ServeUDP] have been called.
func (s *Server) isStarted() (ok bool) {
	s.lock.RLock()
	started := s.started
	s.lock.RUnlock()

	return started
}

// serveDNS serves a DNS response.  rw and r must not be nil.
func (s *Server) serveDNS(rw ResponseWriter, r *dns.Msg) (err error) {
	if r == nil || len(r.Question) != 1 || r.Response {
		return ErrInvalidQuery
	}

	s.logger().Debug("handling a DNS query", "question", r.Question[0].Name)

	handler := s.Handler
	if handler == nil {
		handler = DefaultHandler
	}

	err = handler.ServeDNS(rw, r)
	if err != nil {
		s.logger().Debug("error while handling a DNS query", slogutil.KeyError, err)

		reply := &dns.Msg{}
		reply.SetRcode(r, dns.RcodeServerFailure)
		_ = rw.WriteMsg(reply)
	}

	return nil
}

// encrypt encrypts DNSCrypt response.  m must not be nil.
func (s *Server) encrypt(m *dns.Msg, q EncryptedQuery) (encrypted []byte, err error) {
	r := EncryptedResponse{
		EsVersion: q.EsVersion,
		Nonce:     q.Nonce,
	}
	packet, err := m.Pack()
	if err != nil {
		return nil, err
	}

	sharedKey, err := computeSharedKey(q.EsVersion, &s.ResolverCert.ResolverSk, &q.ClientPk)
	if err != nil {
		return nil, err
	}

	return r.Encrypt(packet, sharedKey)
}

// decrypt decrypts the incoming message and returns a DNS message to process.
func (s *Server) decrypt(b []byte) (msg *dns.Msg, query EncryptedQuery, err error) {
	query = EncryptedQuery{
		EsVersion:   s.ResolverCert.EsVersion,
		ClientMagic: s.ResolverCert.ClientMagic,
	}
	decrypted, err := query.Decrypt(b, s.ResolverCert.ResolverSk)
	if err != nil {
		return nil, query, err
	}

	msg = &dns.Msg{}
	err = msg.Unpack(decrypted)
	if err != nil {
		return nil, query, err
	}

	return msg, query, nil
}

// handleHandshake handles a TXT request that requests certificate data.
func (s *Server) handleHandshake(b []byte, certTxt string) (res []byte, err error) {
	m := new(dns.Msg)
	err = m.Unpack(b)
	if err != nil {
		return nil, err
	}

	if len(m.Question) != 1 || m.Response {
		return nil, ErrInvalidQuery
	}

	q := m.Question[0]
	providerName := dns.Fqdn(s.ProviderName)

	qName := strings.ToLower(q.Name)
	if q.Qtype != dns.TypeTXT || qName != providerName {
		return nil, ErrInvalidQuery
	}

	reply := new(dns.Msg)
	reply.SetReply(m)
	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeTXT,
			Ttl:    60,
			Class:  dns.ClassINET,
		},
		Txt: []string{
			certTxt,
		},
	}
	reply.Answer = append(reply.Answer, txt)

	// These bits are important for the old dnscrypt-proxy versions.
	reply.Authoritative = true
	reply.RecursionAvailable = true

	return reply.Pack()
}

// validate checks if the Server config is properly set.
func (s *Server) validate() (err error) {
	if s.ResolverCert == nil {
		return errors.Annotate(ErrServerConfig, "ResolverCert is required")
	}

	if !s.ResolverCert.VerifyDate() {
		return errors.Annotate(ErrServerConfig, "ResolverCert date is not valid")
	}

	if s.ProviderName == "" {
		return errors.Annotate(ErrServerConfig, "ProviderName must be set")
	}

	return nil
}

// getCertTXT serializes the cert TXT record that are to be sent to the client.
func (s *Server) getCertTXT() (cert string, err error) {
	certBuf, err := s.ResolverCert.Serialize()
	if err != nil {
		return "", err
	}

	cert = packTxtString(certBuf)

	return cert, nil
}
