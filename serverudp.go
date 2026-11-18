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
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// encryptionFunc is a function for encrypting server response.
type encryptionFunc func(m *dns.Msg, q *encryptedQuery) (encrypted []byte, err error)

// udpResponseWriter is the implementation of the [ResponseWriter] interface for
// UDP.
type udpResponseWriter struct {
	// conn contains UDP connection.  It must not be nil.
	conn net.PacketConn

	// sess contains the UDP session.  It must not be nil.
	sess netutil.PacketSession

	// logger is used for logging UDP response writer operations.  It must not
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
var _ ResponseWriter = &udpResponseWriter{}

// LocalAddr implements the [ResponseWriter] interface for *udpResponseWriter.
func (w *udpResponseWriter) LocalAddr() (addr net.Addr) {
	return w.conn.LocalAddr()
}

// RemoteAddr implements the [ResponseWriter] interface for *udpResponseWriter.
func (w *udpResponseWriter) RemoteAddr() (addr net.Addr) {
	return w.sess.RemoteAddr()
}

// WriteMsg implements the [ResponseWriter] interface for *udpResponseWriter.
func (w *udpResponseWriter) WriteMsg(ctx context.Context, m *dns.Msg) (err error) {
	normalize(ProtoUDP, w.req, m)

	res, err := w.encrypt(m, w.query)
	if err != nil {
		w.logger.DebugContext(ctx, "failed to encrypt DNS query", slogutil.KeyError, err)

		return fmt.Errorf("encrypting dns query: %w", err)
	}

	_, err = netutil.WriteToSession(w.conn, res, w.sess)

	return errors.Annotate(err, "writing to udp session: %w")
}

// serveUDP reads and handles UDP messages.  It blocks the calling goroutine and
// to stop it you need to close the listener or call [Server.Shutdown].
func (s *Server) serveUDP(ctx context.Context) (err error) {
	defer slogutil.RecoverAndLog(ctx, s.logger)

	srvWg, err := s.prepareServeUDP()
	if err != nil {
		return err
	}

	udpWg := &sync.WaitGroup{}
	defer s.cleanUpUDP(srvWg, udpWg)

	s.logger.InfoContext(ctx, "entering dnscrypt udp listening loop")
	certTxt := s.getCertTXT()

	for s.isStarted() {
		err = ctx.Err()
		if err != nil {
			return fmt.Errorf("serving udp: %w", err)
		}

		var stopped bool
		stopped, err = s.serveUDPLoop(ctx, udpWg, certTxt)
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

// serveUDPLoop reads UDP messages and runs goroutines to handle them.  It also
// handles server shutdown.  It returns true if the server has stopped.  udpWg
// must not be nil.
func (s *Server) serveUDPLoop(
	ctx context.Context,
	udpWg *sync.WaitGroup,
	certTxt string,
) (stopped bool, err error) {
	b, sess, err := s.readUDPMsg()
	if err != nil {
		return s.handleConnectionAcceptError(ctx, err, s.proto)
	}

	if len(b) < minDNSPacketSize {
		return false, nil
	}

	err = s.sema.Acquire(ctx)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to acquire semaphore", slogutil.KeyError, err)

		return false, nil
	}

	udpWg.Go(func() {
		defer s.sema.Release()

		defer slogutil.RecoverAndLog(ctx, s.logger)

		s.serveUDPMsg(ctx, b, certTxt, sess)
	})

	return false, nil
}

// prepareServeUDP prepares the server and listener for DNSCrypt service.
func (s *Server) prepareServeUDP() (srvWg *sync.WaitGroup, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	srvWg = s.wg
	srvWg.Add(1)

	return srvWg, nil
}

// cleanUpUDP waits until all UDP messages before cleaning up.  udpWg must not
// be nil.
func (s *Server) cleanUpUDP(srvWg, udpWg *sync.WaitGroup) {
	udpWg.Wait()

	s.mu.Lock()
	defer s.mu.Unlock()

	srvWg.Done()
}

// readUDPMsg reads incoming UDP message.
func (s *Server) readUDPMsg() (msg []byte, sess netutil.PacketSession, err error) {
	err = s.udpConn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
	if err != nil {
		return nil, nil, fmt.Errorf("setting read deadline: %w", err)
	}

	msg = make([]byte, s.udpSize)
	n, sess, err := netutil.ReadFromSession(s.udpConn, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("reading from udp session: %w", err)
	}

	return msg[:n], sess, nil
}

// serveUDPMsg handles incoming DNS message.  sess must not be nil.  It is
// intended to be used as a goroutine.
func (s *Server) serveUDPMsg(
	ctx context.Context,
	b []byte,
	certTxt string,
	sess netutil.PacketSession,
) {
	if !bytes.Equal(b[:clientMagicSize], s.resolverCert.ClientMagic[:]) {
		reply, err := s.handleHandshake(b, certTxt)
		if err != nil {
			s.logger.DebugContext(
				ctx,
				"failed to process a plain DNS query",
				slogutil.KeyError, err,
			)

			return
		}

		_, _ = netutil.WriteToSession(s.udpConn, reply, sess)

		return
	}

	m, q, err := s.decrypt(b)
	if err != nil {
		s.logger.DebugContext(
			ctx,
			"failed to decrypt incoming message",
			"len", len(b),
			slogutil.KeyError, err,
		)

		return
	}

	rw := &udpResponseWriter{
		conn:    s.udpConn,
		sess:    sess,
		encrypt: s.encrypt,
		req:     m,
		query:   q,
		logger:  s.logger,
	}
	err = s.serveDNS(ctx, rw, m)
	if err != nil {
		s.logger.DebugContext(ctx, "failed to serve DNS query", slogutil.KeyError, err)
	}
}
