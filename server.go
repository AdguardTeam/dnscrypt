package dnscrypt

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/validate"
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

// ServerConfig is the configuration structure for [Server].
type ServerConfig struct {
	// Handler to invoke.  If nil, the [DefaultHandler] is used.
	Handler Handler

	// ResolverCert contains resolver certificate.  It must not be nil.
	ResolverCert *Certificate

	// Logger is a logger instance for Server.  If not set, slog.Default() will
	// be used.
	Logger *slog.Logger

	// ProviderName is a DNSCrypt provider name.
	ProviderName string

	// Addr is the address for server to listen.  It must not be empty.
	Addr netip.AddrPort

	// Proto defines protocol for serving.  It must be one of the following:
	//
	//	- [ProtoTCP]
	//	- [ProtoUDP]
	Proto Proto

	// UDPSize is the default buffer size to use to read incoming UDP messages.
	// If not set it defaults to [defaultUDPSize].
	UDPSize uint
}

// type check
var _ validate.Interface = (*ServerConfig)(nil)

// Validate implements the [validate.Interface] for *ServerConfig.
func (c *ServerConfig) Validate() (err error) {
	errs := []error{
		validate.NotEmpty("ProviderName", c.ProviderName),
		validate.NotEmpty("Addr", c.Addr),
		validate.NotNil("ResolverCert", c.ResolverCert),
		c.Proto.Validate(),
	}

	if c.ResolverCert != nil {
		errs = validate.Append(errs, "ResolverCert", c.ResolverCert)
	}

	return errors.Join(errs...)
}

// Server is a DNSCrypt server implementation.
type Server struct {
	handler      Handler
	resolverCert *Certificate
	logger       *slog.Logger
	// wg tracks active workers (servers).
	wg          *sync.WaitGroup
	udpConn     *net.UDPConn
	tcpListener net.Listener
	// tcpConns tracks active connections.
	//
	// TODO(f.setrakov): Consider using syncutil.Map.
	tcpConns     map[net.Conn]struct{}
	addr         netip.AddrPort
	providerName string
	proto        Proto
	udpSize      uint
	// mu protects concurrent access to listeners, conns, wg and started.
	mu sync.RWMutex
	// started indicates whether the server is processing queries.
	started bool
}

// NewServer returns properly initialized *Server.  conf must be non-nil and
// valid.
func NewServer(conf *ServerConfig) (s *Server, err error) {
	err = conf.Validate()
	if err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &Server{
		handler:      cmp.Or(conf.Handler, defaultDNSCryptHandler),
		resolverCert: conf.ResolverCert,
		providerName: conf.ProviderName,
		addr:         conf.Addr,
		logger:       cmp.Or(conf.Logger, slog.Default()),
		wg:           &sync.WaitGroup{},
		udpSize:      cmp.Or(conf.UDPSize, defaultUDPSize),
		proto:        conf.Proto,
		tcpConns:     map[net.Conn]struct{}{},
	}, nil
}

// LocalAddr returns the local network address for the given protocol, if known.
func (s *Server) LocalAddr() (addr net.Addr) {
	switch s.proto {
	case ProtoTCP:
		if s.tcpListener != nil {
			return s.tcpListener.Addr()
		}
	case ProtoUDP:
		if s.udpConn != nil {
			return s.udpConn.LocalAddr()
		}
	default:
		panic(fmt.Errorf(
			"proto: %w: %q, supported: %q",
			errors.ErrBadEnumValue,
			s.proto,
			[]Proto{ProtoTCP, ProtoUDP},
		))
	}

	return nil
}

// type check
var _ service.Interface = (*Server)(nil)

// Start implements the [service.Interface] for *Server.  It does not block
// calling goroutine.
func (s *Server) Start(ctx context.Context) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return ErrServerAlreadyStarted
	}

	s.started = true

	switch s.proto {
	case ProtoTCP:
		s.tcpListener, err = net.ListenTCP(string(ProtoTCP), net.TCPAddrFromAddrPort(s.addr))
	case ProtoUDP:
		s.udpConn, err = net.ListenUDP(string(ProtoUDP), net.UDPAddrFromAddrPort(s.addr))
	default:
		panic(fmt.Errorf(
			"proto: %w: %q, supported: %q",
			errors.ErrBadEnumValue,
			s.proto,
			[]Proto{ProtoTCP, ProtoUDP},
		))
	}

	if err != nil {
		s.started = false
		s.closeListeners(ctx)

		return fmt.Errorf("listening %s: %w", s.proto, err)
	}

	s.startServe(ctx)

	return nil
}

// closeListeners closes server active network listeners.
func (s *Server) closeListeners(ctx context.Context) {
	if s.tcpListener != nil {
		err := s.tcpListener.Close()
		if err != nil {
			s.logger.WarnContext(ctx, "closing tcp listener", slogutil.KeyError, err)
		}
	}

	if s.udpConn != nil {
		err := s.udpConn.Close()
		if err != nil {
			s.logger.WarnContext(ctx, "closing udp connection", slogutil.KeyError, err)
		}
	}
}

// startServe starts TCP and UDP connection serving loops.  It does not block
// calling goroutine.
func (s *Server) startServe(ctx context.Context) {
	if s.proto == ProtoTCP {
		go s.startServeTCP(ctx)
	}

	if s.proto == ProtoUDP {
		go s.startServeUDP(ctx)
	}
}

// startServeTCP starts TCP serving loop.
func (s *Server) startServeTCP(ctx context.Context) {
	tcpErr := s.serveTCP(ctx)
	if tcpErr != nil {
		// TODO(f.setrakov): Improve error handling.
		s.logger.WarnContext(ctx, "listening tcp failed", slogutil.KeyError, tcpErr)
	}
}

// startServeUDP starts UDP serving loop.
func (s *Server) startServeUDP(ctx context.Context) {
	udpErr := s.serveUDP(ctx)
	if udpErr != nil {
		// TODO(f.setrakov): Improve error handling.
		s.logger.WarnContext(ctx, "listening udp failed", slogutil.KeyError, udpErr)
	}
}

// prepareShutdown prepares the server to shutdown: unblocks reads from all
// connections related to this server, marks the server as stopped.  If the
// server is not started, returns [ErrServerNotStarted].
func (s *Server) prepareShutdown(ctx context.Context) (srvWg *sync.WaitGroup, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		s.logger.InfoContext(ctx, "server is not started")

		return nil, ErrServerNotStarted
	}

	s.started = false

	// NOTE: Avoid closing TCP connections to be able to process queries before
	// shutting everything down.
	for conn := range s.tcpConns {
		_ = conn.SetReadDeadline(longTimeAgo)
	}

	// NOTE: To prevent panics, we should not allow wait group reuse.  See
	// https://github.com/ameshkov/dnscrypt/issues/23.
	prevWg := s.wg
	s.wg = &sync.WaitGroup{}

	return prevWg, nil
}

// Shutdown implements the [service.Interface] for *Server.  It waits until all
// connections are processed and only after that it leaves the method.  If
// context deadline is specified, it will exit earlier.
func (s *Server) Shutdown(ctx context.Context) (err error) {
	s.logger.InfoContext(ctx, "shutting down the dnscrypt server")

	srvWg, err := s.prepareShutdown(ctx)
	if err != nil {
		return fmt.Errorf("preparing shutdown: %w", err)
	}

	s.closeListeners(ctx)

	closed := make(chan struct{})
	go func() {
		defer slogutil.RecoverAndLog(ctx, s.logger)

		srvWg.Wait()
		s.logger.InfoContext(ctx, "serve goroutines finished their work")
		close(closed)
	}()

	select {
	case <-closed:
		s.logger.InfoContext(ctx, "dnscrypt server has been stopped")
	case <-ctx.Done():
		s.logger.InfoContext(ctx, "dnscrypt server shutdown has timed out")
		err = ctx.Err()
	}

	return errors.Annotate(err, "shutting down: %w")
}

// isStarted returns true if the server is processing queries right now.
func (s *Server) isStarted() (ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	started := s.started

	return started
}

// serveDNS serves a DNS response.  rw and r must not be nil.
func (s *Server) serveDNS(ctx context.Context, rw ResponseWriter, r *dns.Msg) (err error) {
	if r == nil || len(r.Question) != 1 || r.Response {
		return ErrInvalidQuery
	}

	s.logger.DebugContext(ctx, "handling a DNS query", "question", r.Question[0].Name)
	err = s.handler.ServeDNS(ctx, rw, r)
	if err == nil {
		return nil
	}

	s.logger.DebugContext(ctx, "error while handling a DNS query", slogutil.KeyError, err)

	reply := &dns.Msg{}
	reply.SetRcode(r, dns.RcodeServerFailure)
	err = rw.WriteMsg(ctx, reply)
	if err != nil {
		return fmt.Errorf("writing message: %w", err)
	}

	return nil
}

// encrypt encrypts DNSCrypt response.  m must not be nil.
func (s *Server) encrypt(m *dns.Msg, q *encryptedQuery) (encrypted []byte, err error) {
	r := &encryptedResponse{
		ESVersion: q.ESVersion,
		Nonce:     q.Nonce,
	}
	packet, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing dns message: %w", err)
	}

	sharedKey, err := computeSharedKey(q.ESVersion, &s.resolverCert.ResolverSk, &q.ClientPk)
	if err != nil {
		return nil, fmt.Errorf("computing shared key: %w", err)
	}

	return r.encrypt(packet, sharedKey)
}

// decrypt decrypts the incoming message and returns a DNS message to process.
func (s *Server) decrypt(b []byte) (msg *dns.Msg, query *encryptedQuery, err error) {
	query = &encryptedQuery{
		ESVersion:   s.resolverCert.ESVersion,
		ClientMagic: s.resolverCert.ClientMagic,
	}
	decrypted, err := query.decrypt(b, s.resolverCert.ResolverSk)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting query: %w", err)
	}

	msg = &dns.Msg{}
	err = msg.Unpack(decrypted)
	if err != nil {
		return nil, nil, fmt.Errorf("unpacking dns message: %w", err)
	}

	return msg, query, nil
}

// handleHandshake handles a TXT request that requests certificate data.
func (s *Server) handleHandshake(b []byte, certTxt string) (res []byte, err error) {
	m := &dns.Msg{}
	err = m.Unpack(b)
	if err != nil {
		return nil, fmt.Errorf("unpacking dns message: %w", err)
	}

	if len(m.Question) != 1 || m.Response {
		return nil, ErrInvalidQuery
	}

	q := m.Question[0]
	providerName := dns.Fqdn(s.providerName)

	qName := strings.ToLower(q.Name)
	if q.Qtype != dns.TypeTXT || qName != providerName {
		return nil, ErrInvalidQuery
	}

	reply := &dns.Msg{}
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

// getCertTXT serializes the cert TXT record that are to be sent to the client.
func (s *Server) getCertTXT() (cert string) {
	// Ignore the error as it is always nil.
	certBuf, _ := s.resolverCert.MarshalBinary()

	return packTxtString(certBuf)
}

// isConnClosed checks if the error signals a closed server connection.
func isConnClosed(err error) (ok bool) {
	if err == nil {
		return false
	}

	nerr, ok := err.(*net.OpError)
	if !ok {
		return false
	}

	if strings.Contains(nerr.Err.Error(), "use of closed network connection") {
		return true
	}

	return false
}
