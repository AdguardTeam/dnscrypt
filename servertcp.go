package dnscrypt

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
)

// tcpResponseWriter is the implementation of the [ResponseWriter] interface for
// TCP.
type tcpResponseWriter struct {
	// tcpConn contains TCP connection.  It must not be nil.
	tcpConn net.Conn

	// logger is used for logging TCP response writer operations.  It must not
	// be nil.
	logger *slog.Logger

	// req contains processed DNS query.
	req *dns.Msg

	// query contains DNSCrypt query properties.  It must not be nil.
	query *encryptedQuery

	// encrypt contains DNSCrypt encryption function.  It must not be nil.
	encrypt encryptionFunc
}

// type check
var _ ResponseWriter = &tcpResponseWriter{}

// LocalAddr implements the [ResponseWriter] interface for *tcpResponseWriter.
func (w *tcpResponseWriter) LocalAddr() (addr net.Addr) {
	return w.tcpConn.LocalAddr()
}

// RemoteAddr implements the [ResponseWriter] interface for *tcpResponseWriter.
func (w *tcpResponseWriter) RemoteAddr() (addr net.Addr) {
	return w.tcpConn.RemoteAddr()
}

// WriteMsg implements the [ResponseWriter] interface for *tcpResponseWriter.
func (w *tcpResponseWriter) WriteMsg(ctx context.Context, m *dns.Msg) (err error) {
	normalize(ProtoTCP, w.req, m)

	res, err := w.encrypt(m, w.query)
	if err != nil {
		w.logger.DebugContext(ctx, "failed to encrypt the DNS query", slogutil.KeyError, err)

		return fmt.Errorf("encrypting query: %w", err)
	}

	return writePrefixed(res, w.tcpConn)
}

// ServeTCP listens for TCP connections and handles them.  It blocks the calling
// goroutine and to stop it you need to close the listener or call
// [Server.Shutdown].  l must not be nil.  It blocks on a successful start.
func (s *Server) ServeTCP(ctx context.Context, l net.Listener) (err error) {
	defer slogutil.RecoverAndLog(ctx, s.logger)

	srvWg := s.prepareServeTCP(l)

	s.logger.InfoContext(ctx, "entering dnscrypt tcp listening loop", "listen_addr", l.Addr())

	tcpWg := &sync.WaitGroup{}
	defer s.cleanUpTCP(srvWg, tcpWg, l)

	certTxt := s.getCertTXT()

	for s.isStarted() {
		var stopped bool
		stopped, err = s.serveTCPLoop(ctx, certTxt, l, tcpWg)
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return err
		}

		if stopped {
			break
		}
	}

	return nil
}

// serveTCPLoop accepts TCP connections and runs goroutines to handle them. It
// also handles server shutdown.  It returns true if the server has stopped. l
// and tcpWg must not be nil.
func (s *Server) serveTCPLoop(
	ctx context.Context,
	certTxt string,
	l net.Listener,
	tcpWg *sync.WaitGroup,
) (stopped bool, err error) {
	conn, err := l.Accept()
	if err != nil {
		if !s.isStarted() {
			return true, nil
		}

		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return false, nil
		}

		if isConnClosed(err) {
			s.logger.InfoContext(ctx, "TCP listener closed, exiting loop")
		} else {
			s.logger.InfoContext(
				ctx,
				"got error when reading from TCP listener",
				slogutil.KeyError, err,
			)
		}

		return true, fmt.Errorf("reading tcp message: %w", err)
	}

	// Track the connection to allow unblocking reads on shutdown.
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tcpConns[conn] = struct{}{}

	tcpWg.Go(func() {
		defer slogutil.RecoverAndLog(ctx, s.logger)

		_ = s.handleTCPConnection(ctx, conn, certTxt)
		_ = conn.Close()

		s.mu.Lock()
		defer s.mu.Unlock()

		delete(s.tcpConns, conn)
	})

	return false, nil
}

// prepareServeTCP prepares the server and listener for DNSCrypt service.  l
// must not be nil.
func (s *Server) prepareServeTCP(l net.Listener) (prevWg *sync.WaitGroup) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.initOnce.Do(s.init)

	// NOTE: We do not check whether the server has already been started, as
	// Serve* methods can be called multiple times.
	s.started = true
	s.tcpListeners[l] = struct{}{}

	srvWg := s.wg
	srvWg.Add(1)

	return srvWg
}

// cleanUpTCP waits until all TCP messages before cleaning up.  tcpWg and l must
// not be nil.
func (s *Server) cleanUpTCP(srvWg, tcpWg *sync.WaitGroup, l net.Listener) {
	tcpWg.Wait()

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tcpListeners, l)

	srvWg.Done()
}

// handleTCPMsg handles a single TCP message.  If this method returns error
// the connection will be closed.  conn must not be nil.
func (s *Server) handleTCPMsg(
	ctx context.Context,
	b []byte,
	conn net.Conn,
	certTxt string,
) (err error) {
	if len(b) < minDNSPacketSize {
		// Ignore the packets that are too short.
		return ErrTooShort
	}

	if !bytes.Equal(b[:clientMagicSize], s.resolverCert.ClientMagic[:]) {
		var reply []byte
		reply, err = s.handleHandshake(b, certTxt)
		if err != nil {
			return fmt.Errorf("failed to process a plain DNS query: %w", err)
		}

		err = writePrefixed(reply, conn)
		if err != nil {
			return fmt.Errorf("failed to write a response: %w", err)
		}

		return nil
	}

	m, q, err := s.decrypt(b)
	if err != nil {
		return fmt.Errorf("failed to decrypt incoming message: %w", err)
	}

	rw := &tcpResponseWriter{
		tcpConn: conn,
		encrypt: s.encrypt,
		req:     m,
		query:   q,
		logger:  s.logger,
	}

	err = s.serveDNS(ctx, rw, m)
	if err != nil {
		return fmt.Errorf("failed to process a DNS query: %w", err)
	}

	return nil
}

// handleTCPConnection handles all queries that are coming to the specified TCP
// connection.  conn must not be nil.
func (s *Server) handleTCPConnection(
	ctx context.Context,
	conn net.Conn,
	certTxt string,
) (err error) {
	timeout := defaultReadTimeout

	for s.isStarted() {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))

		var b []byte
		b, err = readPrefixed(conn)
		if err != nil {
			return fmt.Errorf("reading dns message from connection: %w", err)
		}

		err = s.handleTCPMsg(ctx, b, conn, certTxt)
		if err != nil {
			s.logger.DebugContext(ctx, "failed to process a DNS query", slogutil.KeyError, err)

			return fmt.Errorf("handling tcp message: %w", err)
		}

		timeout = defaultTCPIdleTimeout
	}

	return nil
}
