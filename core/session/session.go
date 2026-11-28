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
	// RunAt: when this run of the app began (unix ms, the device's own
	// clock). A TurnVK server lets the later run of a device hold it.
	RunAt int64

	// OnReset is called when the server says it no longer knows this
	// session (it restarted): the other sessions are likely stale too.
	OnReset func()
	// Logf, if set, gets the session's own notes (a TURN allocation that
	// could not be freed).
	Logf func(format string, args ...any)
	// OnUnfreed, if set, is called when the session's TURN allocation
	// could not be freed: VK keeps counting it until its lifetime ends.
	OnUnfreed func()
	// RTTs, if set, counts every round trip the path's pings measure.
	RTTs *Hist
	// Quiet, if set, is the idle mode the engine switches (quiet.go).
	Quiet *Quiet
	// NetDown, when set, tells whether the device has no network: a
	// silent path is kept then instead of closed (it could not be
	// replaced, nor its allocation freed).
	NetDown func() bool

	// Direct selects the direct protocol (TurnVK servers) instead of
	// DTLS + GETCONF. Keys is the client's WireGuard key pair; ServerKey,
	// if set, is the only server key accepted.
	Direct        bool
	Keys          *Keys
	ServerKey     []byte
	DirectTimeout time.Duration // for the first WELCOME (default 6 s)
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
	case "newer_connection":
		return "this device connected again elsewhere (a newer connection took over)"
	case "server_key":
		return "the server's key does not match the link: not your server, or the server was reinstalled (get a new link)"
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

// QuotaReached reports VK refusing the guest more allocations (486).
func (e *TURNError) QuotaReached() bool {
	s := strings.ToLower(e.Err.Error())
	return strings.Contains(s, "486") || strings.Contains(s, "quota")
}

// Session is an open transport session.
type Session struct {
	ID      int
	Server  string // TURN server used
	Relay   string // relayed address the WDTT server sees
	Config  string // the server's answer to GETCONF ("" for NOCONF)
	Started time.Time

	udp   *net.UDPConn
	tc    *turn.Client
	relay net.PacketConn
	dtls  *dtls.Conn
	// The allocation, for release on Close: TURN server and credentials.
	turnAddr           net.Addr
	turnUser, turnPass string
	turnPeer           *net.UDPAddr // the WDTT server, as the relay sends to it
	renew              renewState   // renew.go
	logf               func(format string, args ...any)
	onUnfreed          func()
	rtts               *Hist
	closed             atomic.Bool
	done               chan struct{}
	once               sync.Once

	RxBytes, TxBytes, RxPackets, TxPackets atomic.Uint64
	// RxLost counts the server's packets lost on this path (direct
	// protocol: gaps in the RTP sequence).
	RxLost atomic.Uint64
	// Pace paces what this session sends (direct protocol, once the server
	// sends FEEDBACK); rx counts what the server sends (read loop only).
	Pace   PathRate
	rx     RxTrack
	LastRx atomic.Int64 // unix nanoseconds
	// NetErrAt: when a send last failed for lack of network, unix ns.
	NetErrAt atomic.Int64
	// RTT is the path's last measured round trip (direct protocol), ns.
	RTT atomic.Int64
	// Lat is the round trip a packet should expect on the path, jitter
	// included: smoothed RTT plus twice its mean deviation (jitter.go), ns;
	// 0 until measured.
	Lat atomic.Int64
	jit jitter // read loop only
	// StatsAck, when set before reading starts, gets the ids of the
	// statistics reports the server acknowledged (stats.go).
	StatsAck func(id uint32)

	// Direct protocol.
	direct    bool
	aead      cipher.AEAD
	peer      *net.UDPAddr
	sealer    *wrap.Sealer
	params    Params
	rbuf      [maxPacket + wrap.MaxOverhead]byte
	mu        sync.Mutex
	pending   []byte    // nonce of the HELLO awaiting its WELCOME
	lastHello time.Time // when the last re-attach HELLO went out
	resetAt   time.Time // first RESET not yet answered by a WELCOME
	denied    atomic.Pointer[error]
	probeAt   atomic.Int64 // last probe not yet answered, unix ns
	// txWait: the first packet sent since the server was last heard from
	// on the path (unix ns); acks: the server confirms what it receives
	// (FEEDBACK), so a path that confirms nothing is dead (Fresh).
	txWait atomic.Int64
	acks   atomic.Bool
	quiet  *Quiet
	// testProbe stands in for the network in tests (testing.go).
	testProbe func(*Session)
}

var handshakeSlots = make(chan struct{}, 4)

// Dial opens a session. The context bounds the setup only.
func Dial(ctx context.Context, p Params) (*Session, error) {
	s := &Session{ID: p.Worker, Server: p.TURNServer, Started: time.Now(), done: make(chan struct{}), quiet: p.Quiet}
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
	s.turnAddr, s.turnUser, s.turnPass, s.logf, s.onUnfreed, s.rtts = turnAddr, p.Username, p.Password, p.Logf, p.OnUnfreed, p.RTTs
	s.turnPeer = p.Peer
	s.renew.mark(time.Now().UnixNano(), monoNow())
	if p.Direct {
		timeout := p.DirectTimeout
		if timeout <= 0 {
			timeout = 6 * time.Second
		}
		if err = s.dialDirect(p, timeout); err != nil {
			return nil, err
		}
		ok = true
		s.LastRx.Store(time.Now().UnixNano())
		go s.pingLoop()
		return s, nil
	}
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
	if s.direct {
		return s.readDirectData(b)
	}
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
	if s.direct {
		if err := s.sendDirect(b); err != nil {
			return err
		}
		s.TxBytes.Add(uint64(len(b)))
		s.TxPackets.Add(1)
		s.touch(time.Now().UnixNano())
		return nil
	}
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
	if s.testProbe != nil {
		if !s.Closed() {
			s.markProbe()
			s.testProbe(s)
		}
		return
	}
	if s.direct {
		if !s.Closed() {
			s.probe()
		}
		return
	}
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
		s.bye()
		s.closed.Store(true)
		close(s.done)
		if s.dtls != nil {
			_ = s.dtls.Close()
		}
		if s.relay != nil {
			_ = s.relay.Close() // also stops the readers
		}
		// Free the allocation and wait for VK's answer (release.go), in the
		// background: Close is called from the engine's loops.
		releasing.Add(1)
		go func() {
			defer releasing.Done()
			if s.tc != nil && s.turnAddr != nil {
				r, err := releaseRetry(pionTransactor{s.tc}, s.turnAddr, s.turnUser, s.turnPass, releaseWaits)
				releaseCount[r].Add(1)
				if err != nil && s.logf != nil {
					s.logf("route %d: TURN allocation on %s not freed: %v", s.ID, s.Server, err)
				}
				if err != nil && s.onUnfreed != nil {
					s.onUnfreed()
				}
			}
			if s.tc != nil {
				s.tc.Close()
			}
			if s.udp != nil {
				_ = s.udp.Close()
			}
		}()
	})
}

// releaseCount counts the outcomes of release, by releaseResult.
var releaseCount [4]atomic.Uint64

// ReleaseStats returns how many allocations this side freed, how many
// pion's own request had freed already, and how many were not freed.
func ReleaseStats() (freed, gone, failed uint64) {
	return releaseCount[released].Load(), releaseCount[releaseGone].Load(), releaseCount[releaseFailed].Load()
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
