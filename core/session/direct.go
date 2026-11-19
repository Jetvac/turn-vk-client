package session

// The direct protocol (TurnVK servers): no DTLS. Each TURN allocation is a
// "path" attached to the device with one HELLO; everything else is
// WireGuard, end to end with the server, inside the RTP wrap. Losing a path
// costs nothing but that path, and a server restart costs one HELLO per
// path. See the server's internal/wdtt/direct.go for the layout.

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Jetvac/turn-vk-client/core/wrap"
)

const (
	msgHello   = 0x41
	msgWelcome = 0x42
	msgPing    = 0x44
	msgPong    = 0x45
	msgReset   = 0x46
	msgBye     = 0x47

	directVersion = 1

	pingInterval = 2 * time.Second
	// PathFresh: a path that has answered within this carries traffic;
	// pathDead: one silent for this long is replaced; probeWait: a probed
	// path that has not answered within this is left out at once (less
	// once its round trip is known, see probeLimit); idleProbe: a path
	// that carries packets but has not heard from the server for this
	// long is probed at once instead of at the next ping.
	PathFresh    = 10 * time.Second
	pathDead     = 25 * time.Second
	probeWait    = 2 * time.Second
	probeWaitMin = 500 * time.Millisecond
	idleProbe    = time.Second
	// ackWaitMin: a path whose server confirms what it receives (FEEDBACK,
	// within 50 ms) and has confirmed nothing sent on it for a few round
	// trips, at least this long, stops carrying traffic until it answers.
	ackWaitMin     = 300 * time.Millisecond
	helloRetry     = time.Second
	reattachWithin = 10 * time.Second
)

// WELCOME status codes.
const (
	welcomeOK = iota
	welcomeWrongPassword
	welcomeExpired
	welcomeDeactivated
	welcomeDeviceMismatch
	welcomeNoConf
	welcomeClock
	welcomeStale
)

// ErrNoWelcome means the server never answered HELLO: it does not speak
// the direct protocol (a standard WDTT server), the password is wrong, or
// the server is unreachable.
var ErrNoWelcome = errors.New("no answer to HELLO (wrong password, server unreachable, or not a TurnVK server)")

// clockOffset corrects the HELLO time stamp after a server reports that
// this device's clock is off (ms).
var clockOffset atomic.Int64

func nowMs() int64 { return time.Now().UnixMilli() + clockOffset.Load() }

// Keys is the client's WireGuard key pair for the direct protocol.
type Keys struct {
	Private [32]byte
	Public  [32]byte
}

// Denied returns the refusal that closed the path, if any.
func (s *Session) Denied() error {
	if e := s.denied.Load(); e != nil {
		return *e
	}
	return nil
}

// Direct reports whether the session speaks the direct protocol.
func (s *Session) Direct() bool { return s.direct }

// Fresh reports whether the path has heard from the server lately (always
// true for DTLS sessions, which have no pings).
func (s *Session) Fresh(now time.Time) bool {
	if !s.direct {
		return true
	}
	rx, n := s.LastRx.Load(), now.UnixNano()
	if p := s.probeAt.Load(); p > rx && n-p > probeLimit(s.RTT.Load()) {
		return false
	}
	if w := s.txWait.Load(); w > rx && s.acks.Load() && n-w > ackLimit(s.RTT.Load()) {
		return false
	}
	return n-rx < s.quiet.freshFor(n)
}

// ackLimit is how long a path whose server confirms what it receives may
// go without answering a packet sent on it (ns): a few round trips, at
// least ackWaitMin, at most probeWait.
func ackLimit(rtt int64) int64 {
	if rtt <= 0 {
		return int64(probeWait)
	}
	return min(int64(probeWait), max(int64(ackWaitMin), 3*rtt+int64(100*time.Millisecond)))
}

// probeLimit is how long a probed path may take to answer (ns): a few
// round trips, at least probeWaitMin, at most probeWait (also while the
// round trip is not known yet).
func probeLimit(rtt int64) int64 {
	if rtt <= 0 {
		return int64(probeWait)
	}
	return min(int64(probeWait), max(int64(probeWaitMin), 4*rtt+int64(300*time.Millisecond)))
}

// touch: a packet went out on the path. One that has not heard from the
// server for idleProbe is pinged now, so that a dead path stops carrying
// traffic within about a second instead of at the next ping.
func (s *Session) touch(now int64) {
	rx := s.LastRx.Load()
	if w := s.txWait.Load(); w <= rx {
		s.txWait.CompareAndSwap(w, now)
	}
	if now-rx < int64(idleProbe) {
		return
	}
	if p := s.probeAt.Load(); p <= rx && s.probeAt.CompareAndSwap(p, now) {
		_ = s.ping()
	}
}

// probe pings the path now; Fresh turns false if no answer comes within
// probeWait.
func (s *Session) probe() {
	if s.probeAt.Load() <= s.LastRx.Load() {
		s.probeAt.Store(time.Now().UnixNano())
	}
	_ = s.ping()
}

// bye tells the server the path is closing, so it stops using it at once.
func (s *Session) bye() {
	if s.direct && s.relay != nil {
		_ = s.sendDirect([]byte{msgBye, directVersion})
	}
}

// Welcome is what the server answered to HELLO.
type welcomeMsg struct {
	status    byte
	serverKey []byte
	addr      netip.Addr
	bits      int
	mtu       int
	keepalive int
	dns       []netip.Addr
	clock     int64
}

func parseWelcome(b []byte, nonce []byte) (welcomeMsg, bool) {
	var w welcomeMsg
	if len(b) < 19 || b[0] != msgWelcome || b[1] != directVersion || !bytes.Equal(b[2:18], nonce) {
		return w, false
	}
	w.status = b[18]
	rest := b[19:]
	switch w.status {
	case welcomeClock:
		if len(rest) >= 8 {
			w.clock = int64(binary.BigEndian.Uint64(rest[:8]))
		}
	case welcomeOK:
		if len(rest) < 41 {
			return w, false
		}
		w.serverKey = append([]byte(nil), rest[:32]...)
		w.addr = netip.AddrFrom4([4]byte(rest[32:36]))
		w.bits = int(rest[36])
		w.mtu = int(binary.BigEndian.Uint16(rest[37:39]))
		w.keepalive = int(rest[39])
		n := int(rest[40])
		rest = rest[41:]
		for i := 0; i < n && len(rest) >= 4; i++ {
			w.dns = append(w.dns, netip.AddrFrom4([4]byte(rest[:4])))
			rest = rest[4:]
		}
	}
	return w, true
}

func (w welcomeMsg) err() error {
	switch w.status {
	case welcomeOK:
		return nil
	case welcomeWrongPassword:
		return &DeniedError{Reason: "wrong_password"}
	case welcomeExpired:
		return &DeniedError{Reason: "expired"}
	case welcomeDeactivated:
		return &DeniedError{Reason: "deactivated"}
	case welcomeDeviceMismatch:
		return &DeniedError{Reason: "device_mismatch"}
	case welcomeNoConf:
		return errors.New("the server has no free address for this device (NOCONF)")
	case welcomeStale:
		return &DeniedError{Reason: "newer_connection"}
	}
	return fmt.Errorf("unknown HELLO answer %d", w.status)
}

// config renders the answer as the INI config the engine reads.
func (w welcomeMsg) config(k *Keys) string {
	var dns []string
	for _, a := range w.dns {
		dns = append(dns, a.String())
	}
	ka := w.keepalive
	if ka == 0 {
		ka = 25
	}
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/%d\nDNS = %s\nMTU = %d\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = %d\n",
		base64.StdEncoding.EncodeToString(k.Private[:]), w.addr, w.bits, strings.Join(dns, ", "), w.mtu,
		base64.StdEncoding.EncodeToString(w.serverKey), ka)
}

func (s *Session) helloBytes(p Params) ([]byte, []byte) {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	b := []byte{msgHello, directVersion}
	b = binary.BigEndian.AppendUint64(b, uint64(nowMs()))
	b = append(b, nonce...)
	b = append(b, p.Keys.Public[:]...)
	dev, gen := p.DeviceID, p.Generation
	if len(dev) > 128 {
		dev = dev[:128]
	}
	if len(gen) > 64 {
		gen = gen[:64]
	}
	b = append(b, 0, byte(len(dev)))
	b = append(b, dev...)
	b = append(b, byte(len(gen)))
	b = append(b, gen...)
	return b, nonce
}

// sendDirect wraps and sends one message on the path.
func (s *Session) sendDirect(b []byte) error {
	if len(b) > maxPacket {
		return errors.New("packet too large")
	}
	bp := wbufs.Get().(*[]byte)
	defer wbufs.Put(bp)
	n := s.sealer.Seal(*bp, b)
	s.Pace.OnSend(binary.BigEndian.Uint16((*bp)[2:4]), time.Now().UnixNano())
	_, err := s.relay.WriteTo((*bp)[:n], s.peer)
	return err
}

// readDirect returns the next unwrapped message from the server.
func (s *Session) readDirect(p []byte) (int, error) {
	for {
		n, from, err := s.relay.ReadFrom(s.rbuf[:])
		if err != nil {
			return 0, err
		}
		if ua, ok := from.(*net.UDPAddr); ok && !ua.IP.Equal(s.peer.IP) {
			continue
		}
		m, err := wrap.Open(s.aead, s.rbuf[:n], p)
		if err != nil || m == 0 {
			continue
		}
		now := time.Now().UnixNano()
		// Count the server's packets on this path and tell it how they
		// come through, so that it paces what it sends (pace.go).
		due := s.rx.Seen(binary.BigEndian.Uint16(s.rbuf[2:4]), now)
		s.RxLost.Store(uint64(s.rx.Lost))
		if due {
			_ = s.sendDirect(s.rx.Feedback(directVersion, now))
		}
		s.LastRx.Store(now)
		return m, nil
	}
}

// attach sends HELLO until WELCOME comes back.
func (s *Session) attach(p Params, deadline time.Time) (welcomeMsg, error) {
	buf := make([]byte, maxPacket)
	clockFixed := false
	for {
		hello, nonce := s.helloBytes(p)
		if err := s.sendDirect(hello); err != nil {
			return welcomeMsg{}, err
		}
		retry := time.Now().Add(helloRetry)
		if retry.After(deadline) {
			retry = deadline
		}
		_ = s.relay.SetReadDeadline(retry)
		for {
			n, err := s.readDirect(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					break
				}
				return welcomeMsg{}, err
			}
			w, ok := parseWelcome(buf[:n], nonce)
			if !ok {
				continue
			}
			if w.status == welcomeClock && !clockFixed && w.clock > 0 {
				clockOffset.Store(w.clock - time.Now().UnixMilli())
				clockFixed = true
				break
			}
			_ = s.relay.SetReadDeadline(time.Time{})
			return w, w.err()
		}
		if !time.Now().Before(deadline) {
			_ = s.relay.SetReadDeadline(time.Time{})
			return welcomeMsg{}, ErrNoWelcome
		}
	}
}

// dialDirect attaches a fresh allocation as a path.
func (s *Session) dialDirect(p Params, timeout time.Duration) error {
	s.direct = true
	s.aead = p.AEAD
	s.peer = p.Peer
	s.sealer = wrap.NewSealer(p.AEAD, p.Mode)
	s.params = p
	w, err := s.attach(p, time.Now().Add(timeout))
	if err != nil {
		return err
	}
	if len(p.ServerKey) == 32 && subtle.ConstantTimeCompare(p.ServerKey, w.serverKey) != 1 {
		return &DeniedError{Reason: "server_key"}
	}
	s.Config = w.config(p.Keys)
	return nil
}

// readDirectData is Read for the direct protocol: it handles PONG, RESET
// and late WELCOMEs and returns WireGuard messages.
func (s *Session) readDirectData(b []byte) (int, error) {
	for {
		n, err := s.readDirect(b)
		if err != nil {
			return 0, err
		}
		switch t := b[0]; {
		case t >= 1 && t <= 4:
			s.RxBytes.Add(uint64(n))
			s.RxPackets.Add(1)
			return n, nil
		case t == msgPong && n >= 10:
			sent := int64(binary.BigEndian.Uint64(b[2:10]))
			if rtt := time.Now().UnixNano() - sent; rtt > 0 && rtt < int64(time.Minute) {
				s.RTT.Store(rtt)
				s.rtts.Add(time.Duration(rtt))
			}
		case t == msgFeedback:
			s.acks.Store(true)
			s.Pace.OnFeedback(b[:n], time.Now().UnixNano())
		case t == msgStatsAck && n >= 6:
			if f := s.StatsAck; f != nil {
				f(binary.BigEndian.Uint32(b[2:6]))
			}
		case t == msgReset:
			s.reattach()
		case t == msgWelcome && n >= 19:
			s.mu.Lock()
			nonce := s.pending
			s.mu.Unlock()
			w, ok := parseWelcome(b[:n], nonce)
			if !ok {
				continue
			}
			if w.status == welcomeClock && w.clock > 0 {
				clockOffset.Store(w.clock - time.Now().UnixMilli())
				s.mu.Lock()
				s.pending, s.lastHello = nil, time.Time{}
				s.mu.Unlock()
				s.reattach()
				continue
			}
			if err := w.err(); err != nil {
				s.denied.Store(&err)
				return 0, err
			}
			if len(s.params.ServerKey) == 32 && subtle.ConstantTimeCompare(s.params.ServerKey, w.serverKey) != 1 {
				err := error(&DeniedError{Reason: "server_key"})
				s.denied.Store(&err)
				return 0, err
			}
			s.mu.Lock()
			s.pending, s.resetAt = nil, time.Time{}
			s.mu.Unlock()
		}
	}
}

// reattach answers a RESET: the server lost the path (it restarted, or the
// path was idle); one HELLO brings it back. The server has most likely lost
// the WireGuard session too, so the engine re-keys.
func (s *Session) reattach() {
	s.mu.Lock()
	if time.Since(s.lastHello) < helloRetry {
		s.mu.Unlock()
		return
	}
	hello, nonce := s.helloBytes(s.params)
	s.pending, s.lastHello = nonce, time.Now()
	if s.resetAt.IsZero() {
		s.resetAt = time.Now()
	}
	s.mu.Unlock()
	_ = s.sendDirect(hello)
	if s.params.OnReset != nil {
		go s.params.OnReset()
	}
}

// pingLoop keeps the path alive, measures it, and closes it when the server
// stops answering or does not take it back after a reset. While idle
// (quiet.go) it pings only with the other routes, at each burst.
func (s *Session) pingLoop() {
	q := s.quiet
	wait := pingInterval
	t := time.NewTimer(wait)
	defer t.Stop()
	// Wall clock: it runs on while the device sleeps, the timer does not.
	lastTick, woke := time.Now().UnixNano(), int64(0)
	for {
		burst := q.woken()
		select {
		case <-s.done:
			return
		case <-t.C:
		case <-burst:
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
		}
		if wall := time.Now().UnixNano(); wall-lastTick > int64(wait+2*pingInterval) {
			woke = wall // the device slept: the silence is not the path's
		}
		lastTick = time.Now().UnixNano()
		// Idle: the next ping comes with the next burst (the timer only
		// stands in for one that never comes).
		wait = pingInterval
		if q.On() {
			wait = 2 * QuietPing
		}
		t.Reset(wait)
		s.mu.Lock()
		resetAt, pending := s.resetAt, s.pending != nil
		s.mu.Unlock()
		if pending && !resetAt.IsZero() {
			if time.Since(resetAt) > reattachWithin {
				s.Close()
				return
			}
			// Repeat the HELLO: the answer may have been lost.
			s.mu.Lock()
			s.lastHello = time.Time{}
			s.mu.Unlock()
			s.reattach()
			continue
		}
		now := time.Now().UnixNano()
		if now-max(s.LastRx.Load(), woke) > q.deadAfter(now) {
			// The allocation died without telling (VK dropped it, the
			// network changed): the engine opens a new one.
			s.Close()
			return
		}
		// Every ping is also a probe: a path that does not answer within
		// probeWait stops carrying traffic until it does (about 4 s after
		// it went silent instead of PathFresh).
		if s.probeAt.Load() <= s.LastRx.Load() {
			s.probeAt.Store(time.Now().UnixNano())
		}
		if s.ping() != nil {
			s.Close()
			return
		}
	}
}

// Silent returns how long the path has not heard from the server.
func (s *Session) Silent(now time.Time) time.Duration {
	return time.Duration(now.UnixNano() - s.LastRx.Load())
}

// ping measures the path's round trip and reports the loss seen on it:
// cumulative packets received from the server and lost on the way (the
// server paces the path by it).
func (s *Session) ping() error {
	b := make([]byte, 20)
	b[0], b[1] = msgPing, directVersion
	binary.BigEndian.PutUint64(b[2:10], uint64(time.Now().UnixNano()))
	rtt := s.RTT.Load() / int64(time.Millisecond)
	if rtt > 65535 {
		rtt = 65535
	}
	binary.BigEndian.PutUint16(b[10:12], uint16(rtt))
	binary.BigEndian.PutUint32(b[12:16], uint32(s.RxPackets.Load()))
	binary.BigEndian.PutUint32(b[16:20], uint32(s.RxLost.Load()))
	return s.sendDirect(b)
}
