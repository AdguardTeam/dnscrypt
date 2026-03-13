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

// TCPResponseWriter is the implementation of the [ResponseWriter] interface for
// TCP.
type TCPResponseWriter struct {
	// tcpConn contains TCP connection.  It must not be nil.
	tcpConn net.Conn

	// logger is used for logging TCP response writer operations.  It must not
	// be nil.
	logger *slog.Logger

	// req contains processed DNS query.
	req *dns.Msg

	// encrypt contains DNSCrypt encryption function.
	encrypt encryptionFunc

	// query contains DNSCrypt query properties.
	query EncryptedQuery
}

// type check
var _ ResponseWriter = &TCPResponseWriter{}

// LocalAddr implements the [ResponseWriter] interface for *TCPResponseWriter.
func (w *TCPResponseWriter) LocalAddr() (addr net.Addr) {
	return w.tcpConn.LocalAddr()
}

// RemoteAddr implements the [ResponseWriter] interface for *TCPResponseWriter.
func (w *TCPResponseWriter) RemoteAddr() (addr net.Addr) {
	return w.tcpConn.RemoteAddr()
}

// WriteMsg implements the [ResponseWriter] interface for *TCPResponseWriter.
func (w *TCPResponseWriter) WriteMsg(ctx context.Context, m *dns.Msg) (err error) {
	normalize(ProtoTCP, w.req, m)

	res, err := w.encrypt(m, w.query)
	if err != nil {
		w.logger.DebugContext(ctx, "failed to encrypt the DNS query", slogutil.KeyError, err)

		return err
	}

	return writePrefixed(res, w.tcpConn)
}

// ServeTCP listens for TCP connections and handles them.  It blocks the calling
// goroutine and to stop it you need to close the listener or call
// [Server.Shutdown].  l must not be nil.
func (s *Server) ServeTCP(ctx context.Context, l net.Listener) (err error) {
	err = s.prepareServeTCP(l)
	if err != nil {
		return err
	}

	s.logger.InfoContext(ctx, "entering DNSCrypt TCP listening loop", "listenAddr", l.Addr())

	tcpWg := &sync.WaitGroup{}
	defer s.cleanUpTCP(tcpWg, l)

	s.wg.Add(1)

	certTxt, err := s.getCertTXT()
	if err != nil {
		return err
	}

	for s.isStarted() {
		var conn net.Conn
		conn, err = l.Accept()
		if err != nil {
			if !s.isStarted() {
				break
			}

			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}

			if isConnClosed(err) {
				s.logger.InfoContext(ctx, "TCP listener closed, exiting loop")
			} else {
				s.logger.InfoContext(ctx, "got error when reading from UDP listen", slogutil.KeyError, err)
			}

			break
		}

		// Track the connection to allow unblocking reads on shutdown.
		s.lock.Lock()
		s.tcpConns[conn] = struct{}{}
		s.lock.Unlock()

		tcpWg.Add(1)
		go func() {
			_ = s.handleTCPConnection(ctx, conn, certTxt)

			_ = conn.Close()
			s.lock.Lock()
			delete(s.tcpConns, conn)
			s.lock.Unlock()
			tcpWg.Done()
		}()
	}

	return nil
}

// prepareServeTCP prepares the server and listener for DNSCrypt service.  l
// must not be nil.
func (s *Server) prepareServeTCP(l net.Listener) (err error) {
	err = s.validate()
	if err != nil {
		return err
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	s.initOnce.Do(s.init)

	// NOTE: We do not check whether the server has already been started, as
	// Serve* methods can be called multiple times.
	s.started = true
	s.tcpListeners[l] = struct{}{}

	return nil
}

// cleanUpTCP waits until all TCP messages before cleaning up.  tcpWg and l must
// not be nil.
func (s *Server) cleanUpTCP(tcpWg *sync.WaitGroup, l net.Listener) {
	tcpWg.Wait()

	s.lock.Lock()
	delete(s.tcpListeners, l)
	s.lock.Unlock()

	s.wg.Done()
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

	rw := &TCPResponseWriter{
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
//
// TODO(f.setrakov): Improve error handling.
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
			return err
		}

		err = s.handleTCPMsg(ctx, b, conn, certTxt)
		if err != nil {
			s.logger.DebugContext(ctx, "failed to process a DNS query", slogutil.KeyError, err)

			return err
		}

		timeout = defaultTCPIdleTimeout
	}

	return nil
}
