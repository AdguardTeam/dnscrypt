package dnscrypt

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// encryptionFunc is a function for encrypting server response.
type encryptionFunc func(m *dns.Msg, q *encryptedQuery) (encrypted []byte, err error)

// udpResponseWriter is the implementation of the [ResponseWriter] interface for
// UDP.
type udpResponseWriter struct {
	// udpConn contains UDP connection.  It must not be nil.
	//
	// TODO(f.setrakov): Use [net.PacketConn].
	udpConn *net.UDPConn

	// sess is the UDP session.  It must not be nil.
	sess *dns.SessionUDP

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
	return w.udpConn.LocalAddr()
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

	_, err = dns.WriteToSessionUDP(w.udpConn, res, w.sess)

	return errors.Annotate(err, "writing to udp session: %w")
}

// ServeUDP reads and handles UDP messages.  It blocks the calling goroutine and
// to stop it you need to close the listener or call s[Server.Shutdown].  l must
// not be nil.  It blocks on a successful start.
func (s *Server) ServeUDP(ctx context.Context, l *net.UDPConn) (err error) {
	defer slogutil.RecoverAndLog(ctx, s.logger)

	srvWg, err := s.prepareServeUDP(l)
	if err != nil {
		return err
	}

	udpWg := &sync.WaitGroup{}
	defer s.cleanUpUDP(srvWg, udpWg, l)

	s.logger.InfoContext(ctx, "entering dnscrypt udp listening loop", "listen_addr", l.LocalAddr())

	certTxt := s.getCertTXT()

	for s.isStarted() {
		var stopped bool
		stopped, err = s.serveUDPLoop(ctx, l, udpWg, certTxt)
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
// handles server shutdown.  It returns true if the server has stopped.  l and
// udpWg must not be nil.
func (s *Server) serveUDPLoop(
	ctx context.Context,
	l *net.UDPConn,
	udpWg *sync.WaitGroup,
	certTxt string,
) (stopped bool, err error) {
	b, sess, err := s.readUDPMsg(l)
	if err != nil {
		if !s.isStarted() {
			return true, nil
		}

		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			// Note that timeout errors will be here (i.e. hitting
			// ReadDeadline).
			return false, nil
		}

		if isConnClosed(err) {
			s.logger.InfoContext(ctx, "UDP listener closed, exiting loop")
		} else {
			s.logger.InfoContext(ctx, "got error when reading from UDP", slogutil.KeyError, err)
		}

		return false, fmt.Errorf("reading udp message: %w", err)
	}

	if len(b) < minDNSPacketSize {
		return false, nil
	}

	udpWg.Go(func() {
		defer slogutil.RecoverAndLog(ctx, s.logger)

		s.serveUDPMsg(ctx, b, certTxt, sess, l)
	})

	return false, nil
}

// prepareServeUDP prepares the server and listener for DNSCrypt service.  l
// must not be nil.
func (s *Server) prepareServeUDP(l *net.UDPConn) (srvWg *sync.WaitGroup, err error) {
	err = setUDPSocketOptions(l)
	if err != nil {
		return nil, fmt.Errorf("configuring udp socket: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.initOnce.Do(s.init)

	srvWg = s.wg
	srvWg.Add(1)

	// NOTE: We do not check whether the server has already been started, as
	// Serve* methods can be called multiple times.
	s.started = true

	s.udpListeners[l] = struct{}{}

	return srvWg, nil
}

// cleanUpUDP waits until all UDP messages before cleaning up.  udpWg and l must
// not be nil.
func (s *Server) cleanUpUDP(srvWg, udpWg *sync.WaitGroup, l *net.UDPConn) {
	udpWg.Wait()

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.udpListeners, l)

	srvWg.Done()
}

// readUDPMsg reads incoming UDP message.  l must not be nil.
func (s *Server) readUDPMsg(l *net.UDPConn) (msg []byte, sess *dns.SessionUDP, err error) {
	err = l.SetReadDeadline(time.Now().Add(defaultReadTimeout))
	if err != nil {
		return nil, nil, fmt.Errorf("setting read deadline: %w", err)
	}

	msg = make([]byte, s.udpSize)
	n, sess, err := dns.ReadFromSessionUDP(l, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("reading from udp session: %w", err)
	}

	return msg[:n], sess, nil
}

// serveUDPMsg handles incoming DNS message.  sess and l must not be nil.  It is
// intended to be used as a goroutine.
func (s *Server) serveUDPMsg(
	ctx context.Context,
	b []byte,
	certTxt string,
	sess *dns.SessionUDP,
	l *net.UDPConn,
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

		_, _ = dns.WriteToSessionUDP(l, reply, sess)

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
		udpConn: l,
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

// setUDPSocketOptions configures the UDP socket for use with
// [dns.ReadFromSessionUDP] and [dns.WriteToSessionUDP].  conn must not be nil.
func setUDPSocketOptions(conn *net.UDPConn) (err error) {
	if runtime.GOOS == "windows" {
		return nil
	}

	// We don't know if this a IPv4-only, IPv6-only or a IPv4-and-IPv6
	// connection.  Try enabling receiving of ECN and packet info for both IP
	// versions.  We expect at least one of those syscalls to succeed.
	err6 := ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	err4 := ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
	if err6 != nil && err4 != nil {
		return err4
	}

	return nil
}
