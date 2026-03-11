package dnscrypt

import (
	"bytes"
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
type encryptionFunc func(m *dns.Msg, q EncryptedQuery) (encrypted []byte, err error)

// UDPResponseWriter is the implementation of the [ResponseWriter] interface for
// UDP.
type UDPResponseWriter struct {
	// udpConn contains UDP connection.  It must not be nil.
	udpConn *net.UDPConn

	// sess is the UDP session.  It must not be nil.
	sess *dns.SessionUDP

	// logger is used for logging UDP response writer operations.  It must not
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
var _ ResponseWriter = &UDPResponseWriter{}

// LocalAddr implements the [ResponseWriter] interface for *UDPResponseWriter.
func (w *UDPResponseWriter) LocalAddr() (addr net.Addr) {
	return w.udpConn.LocalAddr()
}

// RemoteAddr implements the [ResponseWriter] interface for *UDPResponseWriter.
func (w *UDPResponseWriter) RemoteAddr() (addr net.Addr) {
	return w.sess.RemoteAddr()
}

// WriteMsg implements the [ResponseWriter] interface for *UDPResponseWriter.
func (w *UDPResponseWriter) WriteMsg(m *dns.Msg) (err error) {
	normalize(ProtoUDP, w.req, m)

	res, err := w.encrypt(m, w.query)
	if err != nil {
		w.logger.Debug("failed to encrypt DNS query", slogutil.KeyError, err)

		return err
	}

	_, err = dns.WriteToSessionUDP(w.udpConn, res, w.sess)

	return err
}

// ServeUDP implements the [ServerDNSCrypt] interface for *Server.  It blocks
// the calling goroutine and to stop it you need to close the listener or call
// [Server.Shutdown].  l must not be nil.
func (s *Server) ServeUDP(l *net.UDPConn) (err error) {
	err = s.prepareServeUDP(l)
	if err != nil {
		return err
	}

	// Tracks UDP handling goroutines.
	udpWg := &sync.WaitGroup{}
	defer s.cleanUpUDP(udpWg, l)

	// Track active goroutine.
	s.wg.Add(1)

	s.logger().Info("entering DNSCrypt UDP listening loop", "listen_addr", l.LocalAddr())

	// Serialize the cert right away and prepare it to be sent to the client.
	certTxt, err := s.getCertTXT()
	if err != nil {
		return err
	}

	for s.isStarted() {
		var b []byte
		var sess *dns.SessionUDP
		b, sess, err = s.readUDPMsg(l)
		// Check the error code and exit loop if necessary.
		if err != nil {
			if !s.isStarted() {
				// Stopped gracefully
				return nil
			}

			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// Note that timeout errors will be here (i.e. hitting
				// ReadDeadline).
				continue
			}

			if isConnClosed(err) {
				s.logger().Info("UDP listener closed, exiting loop")
			} else {
				s.logger().Info("got error when reading from UDP", slogutil.KeyError, err)
			}

			return err
		}

		if len(b) < minDNSPacketSize {
			// Ignore the packets that are too short.
			continue
		}

		udpWg.Add(1)
		go func() {
			s.serveUDPMsg(b, certTxt, sess, l)
			udpWg.Done()
		}()
	}

	return nil
}

// prepareServeUDP prepares the server and listener for DNSCrypt service.  l
// must not be nil.
func (s *Server) prepareServeUDP(l *net.UDPConn) (err error) {
	err = s.validate()
	if err != nil {
		return err
	}

	err = setUDPSocketOptions(l)
	if err != nil {
		return err
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	s.initOnce.Do(s.init)

	// NOTE: We do not check whether the server has already been started, as
	// Serve* methods can be called multiple times.
	s.started = true

	// Track an active UDP listener.
	s.udpListeners[l] = struct{}{}

	return err
}

// cleanUpUDP waits until all UDP messages before cleaning up.  udpWg and l must
// not be nil.
func (s *Server) cleanUpUDP(udpWg *sync.WaitGroup, l *net.UDPConn) {
	udpWg.Wait()

	s.lock.Lock()
	delete(s.udpListeners, l)
	s.lock.Unlock()

	s.wg.Done()
}

// readUDPMsg reads incoming UDP message.  l must not be nil.
func (s *Server) readUDPMsg(l *net.UDPConn) (msg []byte, sess *dns.SessionUDP, err error) {
	err = l.SetReadDeadline(time.Now().Add(defaultReadTimeout))
	if err != nil {
		return nil, nil, fmt.Errorf("setting read deadline: %w", err)
	}

	msg = make([]byte, s.UDPSize)
	n, sess, err := dns.ReadFromSessionUDP(l, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("reading from udp session: %w", err)
	}

	return msg[:n], sess, err
}

// serveUDPMsg handles incoming DNS message.  sess and l must not be nil.
func (s *Server) serveUDPMsg(b []byte, certTxt string, sess *dns.SessionUDP, l *net.UDPConn) {
	if !bytes.Equal(b[:clientMagicSize], s.ResolverCert.ClientMagic[:]) {
		reply, err := s.handleHandshake(b, certTxt)
		if err != nil {
			s.logger().Debug("failed to process a plain DNS query", slogutil.KeyError, err)

			return
		}

		_, _ = dns.WriteToSessionUDP(l, reply, sess)

		return
	}

	m, q, err := s.decrypt(b)
	if err == nil {
		rw := &UDPResponseWriter{
			udpConn: l,
			sess:    sess,
			encrypt: s.encrypt,
			req:     m,
			query:   q,
			logger:  s.logger(),
		}
		err = s.serveDNS(rw, m)
		if err != nil {
			s.logger().Debug("failed to serve DNS query", slogutil.KeyError, err)
		}
	} else {
		s.logger().Debug(
			"failed to decrypt incoming message",
			"len",
			len(b),
			slogutil.KeyError,
			err,
		)
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
