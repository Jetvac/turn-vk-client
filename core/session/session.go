// Package session runs one transport session to a WDTT server: a UDP
// socket to a VK TURN server, a TURN allocation, the RTP wrap and a DTLS 1.2
// connection to the server through the relay, opened with GETCONF.
package session

import (
	"context"
	"crypto/cipher"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"

	"github.com/Jetvac/turn-vk-client/core/netx"
	"github.com/Jetvac/turn-vk-client/core/wrap"
)

const (
	// KeepaliveByte is the one-byte message clients send every 15 s.
	KeepaliveByte     = 0xFF
	keepaliveInterval = 15 * time.Second
	handshakeTimeout  = 15 * time.Second
	confTimeout       = 15 * time.Second
	maxPacket         = 2048
)

// Params describe one session.
type Params struct {
	Peer       *net.UDPAddr // the WDTT server
	TURNServer string       // host:port
	Username   string
	Password   string // TURN password
	AEAD       cipher.AEAD
	Mode       wrap.Mode
	Net        *netx.Net

	// GETCONF fields.
	ConnPassword string
	DeviceID     string
	Generation   string
	Worker       int

	// OnReset is called when the server says it no longer knows this
	// session (it restarted): the other sessions are likely stale too.
	OnReset func()
}

// DeniedError is the server refusing the connection password.
type DeniedError struct{ Reason string }

func (e *DeniedError) Error() string {
	switch e.Reason {
	case "wrong_password":
		return "the server rejected the connection password"
	case "expired":
		return "the connection password has expired"
	case "deactivated":
		return "the connection password is disabled"
	case "device_mismatch":
		return "the connection password is bound to another device"
	}
	return "the server denied access (" + e.Reason + ")"
}

// TURNError is a failure of the TURN server (allocation, credentials).
type TURNError struct{ Err error }

func (e *TURNError) Error() string { return "TURN: " + e.Err.Error() }
func (e *TURNError) Unwrap() error { return e.Err }

// CredentialsRejected reports whether new TURN credentials may help.
func (e *TURNError) CredentialsRejected() bool {
	s := strings.ToLower(e.Err.Error())
	for _, k := range []string{"401", "unauthorized", "438", "stale nonce", "437", "allocation mismatch", "486", "quota", "attribute not found", "integrity"} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// Session is an open transport session.
type Session struct {
	ID      int
	Server  string // TURN server used
	Relay   string // relayed address the WDTT server sees
	Config  string // the server's answer to GETCONF ("" for NOCONF)
	Started time.Time

	udp    *net.UDPConn
	tc     *turn.Client
	relay  net.PacketConn
	dtls   *dtls.Conn
	closed atomic.Bool
	done   chan struct{}
	once   sync.Once

	RxBytes, TxBytes, RxPackets, TxPackets atomic.Uint64
	LastRx                                 atomic.Int64 // unix nanoseconds
}

var handshakeSlots = make(chan struct{}, 4)

// Dial opens a session. The context bounds the setup only.
func Dial(ctx context.Context, p Params) (*Session, error) {
	s := &Session{ID: p.Worker, Server: p.TURNServer, Started: time.Now(), done: make(chan struct{})}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()

	turnAddr, err := p.Net.ResolveUDP(ctx, p.TURNServer)
	if err != nil {
		return nil, &TURNError{fmt.Errorf("resolve %s: %w", p.TURNServer, err)}
	}
	if s.udp, err = p.Net.ListenUDP(ctx); err != nil {
		return nil, fmt.Errorf("UDP socket: %w", err)
	}
	_ = s.udp.SetReadBuffer(1 << 20)
	_ = s.udp.SetWriteBuffer(1 << 20)

	s.tc, err = turn.NewClient(&turn.ClientConfig{
		STUNServerAddr:         turnAddr.String(),
		TURNServerAddr:         turnAddr.String(),
		Conn:                   s.udp,
		Username:               p.Username,
		Password:               p.Password,
		RequestedAddressFamily: turn.RequestedAddressFamilyIPv4,
		LoggerFactory:          quietLogger{},
	})
	if err != nil {
		return nil, &TURNError{err}
	}
	if err = s.tc.Listen(); err != nil {
		return nil, &TURNError{err}
	}
	actx, cancel := context.WithTimeout(ctx, 10*time.Second)
	s.relay, err = s.tc.AllocateWithContext(actx)
	cancel()
	if err != nil {
		return nil, &TURNError{fmt.Errorf("allocate: %w", err)}
	}
	s.Relay = s.relay.LocalAddr().String()

	select {
	case handshakeSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	err = s.handshake(ctx, p)
	<-handshakeSlots
	if err != nil {
		return nil, err
	}

	if s.Config, err = s.getconf(p); err != nil {
		return nil, err
	}
	ok = true
	s.LastRx.Store(time.Now().UnixNano())
	go s.keepalive()
	return s, nil
}

func (s *Session) handshake(ctx context.Context, p Params) error {
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return err
	}
	pc := &wrapConn{relay: s.relay, peer: p.Peer, aead: p.AEAD, sealer: wrap.NewSealer(p.AEAD, p.Mode)}
	pc.onReset = func() {
		s.Close()
		if p.OnReset != nil {
			p.OnReset()
		}
	}
	s.dtls, err = dtls.Client(pc, p.Peer, &dtls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true, // the standard server has a self-signed certificate
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	})
	if err != nil {
		return err
	}
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	if err := s.dtls.HandshakeContext(hctx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
			return fmt.Errorf("DTLS handshake timed out (wrong password or server unreachable)")
		}
		return fmt.Errorf("DTLS handshake: %w", err)
	}
	pc.established.Store(true)
	return nil
}

// getconf sends GETCONF the way the original client does; the server
// answers with a WireGuard config, NOCONF or DENIED:<reason>.
func (s *Session) getconf(p Params) (string, error) {
	msg := fmt.Sprintf("GETCONF:9000|%s|%s|%s|%d", p.DeviceID, p.ConnPassword, p.Generation, p.Worker)
	if _, err := s.dtls.Write([]byte(msg)); err != nil {
		return "", fmt.Errorf("GETCONF: %w", err)
	}
	buf := make([]byte, 4096)
	_ = s.dtls.SetReadDeadline(time.Now().Add(confTimeout))
	defer s.dtls.SetReadDeadline(time.Time{})
	for {
		n, err := s.dtls.Read(buf)
		if err != nil {
			return "", fmt.Errorf("GETCONF answer: %w", err)
		}
		r := string(buf[:n])
		switch {
		case n == 1 && buf[0] == KeepaliveByte:
			continue
		case r == "NOCONF":
			return "", nil
		case strings.HasPrefix(r, "DENIED:"):
			return "", &DeniedError{Reason: strings.TrimPrefix(r, "DENIED:")}
		case strings.Contains(r, "[Interface]"):
			return r, nil
		}
		// Anything else is a WireGuard packet that raced the answer.
	}
}

func (s *Session) keepalive() {
	t := time.NewTicker(keepaliveInterval)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			if _, err := s.dtls.Write([]byte{KeepaliveByte}); err != nil {
				s.Close()
				return
			}
		}
	}
}

// Read returns the next packet from the server, skipping keepalives.
func (s *Session) Read(b []byte) (int, error) {
	for {
		n, err := s.dtls.Read(b)
		if err != nil {
			return 0, err
		}
		s.LastRx.Store(time.Now().UnixNano())
		if n == 1 && b[0] == KeepaliveByte {
			continue
		}
		s.RxBytes.Add(uint64(n))
		s.RxPackets.Add(1)
		return n, nil
	}
}

// Write sends one packet to the server.
func (s *Session) Write(b []byte) error {
	if _, err := s.dtls.Write(b); err != nil {
		return err
	}
	s.TxBytes.Add(uint64(len(b)))
	s.TxPackets.Add(1)
	return nil
}

// Probe sends a keepalive; a server that lost the session answers it with
// a reset, which closes the session.
func (s *Session) Probe() {
	if !s.Closed() {
		_, _ = s.dtls.Write([]byte{KeepaliveByte})
	}
}

// Done is closed when the session is closed.
func (s *Session) Done() <-chan struct{} { return s.done }

// Closed reports whether Close was called.
func (s *Session) Closed() bool { return s.closed.Load() }

// Close tears the session down (DTLS close_notify, TURN deallocation).
func (s *Session) Close() {
	s.once.Do(func() {
		s.closed.Store(true)
		close(s.done)
		if s.dtls != nil {
			_ = s.dtls.Close()
		}
		if s.relay != nil {
			_ = s.relay.Close()
		}
		if s.tc != nil {
			s.tc.Close()
		}
		if s.udp != nil {
			_ = s.udp.Close()
		}
	})
}

// wrapConn is the relay as DTLS sees it: datagrams to and from the server,
// wrapped in RTP on the way.
type wrapConn struct {
	relay  net.PacketConn
	peer   *net.UDPAddr
	aead   cipher.AEAD
	sealer *wrap.Sealer
	rbuf   [maxPacket + wrap.MaxOverhead]byte

	established atomic.Bool
	onReset     func()
}

var errServerReset = errors.New("the server reset the session")

var debug = os.Getenv("TURNVK_DEBUG") != ""

var wbufs = sync.Pool{New: func() any { b := make([]byte, maxPacket+wrap.MaxOverhead); return &b }}

func (w *wrapConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, from, err := w.relay.ReadFrom(w.rbuf[:])
		if err != nil {
			return 0, nil, err
		}
		if ua, ok := from.(*net.UDPAddr); ok && !ua.IP.Equal(w.peer.IP) {
			continue
		}
		m, err := wrap.Open(w.aead, w.rbuf[:n], p)
		if err != nil {
			continue
		}
		// An unencrypted (epoch 0) alert after the handshake means the
		// server no longer knows this session (it restarted or dropped
		// it). The DTLS library ignores such alerts, so act on it here.
		if debug && w.established.Load() && p[0] != 23 && p[0] != 25 {
			log.Printf("session: record type %d epoch %d len %d", p[0], int(p[3])<<8|int(p[4]), m)
		}
		if w.established.Load() && m >= 13 && p[0] == 21 && p[3] == 0 && p[4] == 0 {
			if w.onReset != nil {
				go w.onReset()
			}
			return 0, nil, errServerReset
		}
		return m, w.peer, nil
	}
}

func (w *wrapConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if len(p) > maxPacket {
		return 0, errors.New("packet too large")
	}
	bp := wbufs.Get().(*[]byte)
	defer wbufs.Put(bp)
	n := w.sealer.Seal(*bp, p)
	if _, err := w.relay.WriteTo((*bp)[:n], w.peer); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wrapConn) Close() error                       { return w.relay.Close() }
func (w *wrapConn) LocalAddr() net.Addr                { return w.relay.LocalAddr() }
func (w *wrapConn) SetDeadline(t time.Time) error      { return w.relay.SetDeadline(t) }
func (w *wrapConn) SetReadDeadline(t time.Time) error  { return w.relay.SetReadDeadline(t) }
func (w *wrapConn) SetWriteDeadline(t time.Time) error { return w.relay.SetWriteDeadline(t) }

type quietLogger struct{}

func (quietLogger) NewLogger(string) logging.LeveledLogger {
	return logging.NewDefaultLeveledLoggerForScope("", logging.LogLevelDisabled, nil)
}
