package session

import (
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/Jetvac/turn-vk-client/core/wrap"
)

// A path whose ping went unanswered for probeWait stops carrying traffic,
// and carries it again once anything arrives.
func TestFreshAfterUnansweredPing(t *testing.T) {
	now := time.Now()
	s := &Session{direct: true}
	s.LastRx.Store(now.Add(-3 * time.Second).UnixNano())
	s.probeAt.Store(now.Add(-time.Second).UnixNano())
	if !s.Fresh(now) {
		t.Fatal("left out before probeWait passed")
	}
	s.probeAt.Store(now.Add(-probeWait - time.Millisecond).UnixNano())
	if s.Fresh(now) {
		t.Fatal("still fresh after an unanswered ping")
	}
	s.LastRx.Store(now.UnixNano())
	if !s.Fresh(now) {
		t.Fatal("not fresh after an answer")
	}
	if got := s.Silent(now.Add(7 * time.Second)); got != 7*time.Second {
		t.Fatalf("Silent = %v", got)
	}
}

// countConn is a relay that only counts what goes out.
type countConn struct {
	net.PacketConn
	n int
}

func (c *countConn) WriteTo(b []byte, _ net.Addr) (int, error) { c.n++; return len(b), nil }

// A path that carries packets but has not heard from the server for
// idleProbe is pinged at once (once until it answers), and is left out
// after a few round trips without an answer instead of probeWait.
func TestTouchProbesIdlePath(t *testing.T) {
	aead, _ := chacha20poly1305.New(make([]byte, 32))
	relay := &countConn{}
	s := &Session{direct: true, relay: relay, aead: aead, sealer: wrap.NewSealer(aead, wrap.Audio), peer: &net.UDPAddr{}}
	now := time.Now()
	s.LastRx.Store(now.Add(-500 * time.Millisecond).UnixNano())
	s.RTT.Store(int64(15 * time.Millisecond))
	s.touch(now.UnixNano())
	if relay.n != 0 {
		t.Fatal("probed a path that heard from the server lately")
	}
	s.LastRx.Store(now.Add(-2 * time.Second).UnixNano())
	s.touch(now.UnixNano())
	s.touch(now.Add(100 * time.Millisecond).UnixNano())
	if relay.n != 1 {
		t.Fatalf("%d probes, want 1", relay.n)
	}
	if !s.Fresh(now.Add(400 * time.Millisecond)) {
		t.Fatal("left out before the answer was due")
	}
	if s.Fresh(now.Add(probeWaitMin + 10*time.Millisecond)) {
		t.Fatal("still carrying traffic without an answer")
	}
	if got := time.Duration(probeLimit(0)); got != probeWait {
		t.Fatalf("limit with no round trip known: %v", got)
	}
	if got := time.Duration(probeLimit(int64(time.Second))); got != probeWait {
		t.Fatalf("limit on a slow path: %v", got)
	}
}

// A path whose server confirms what it receives stops carrying traffic a
// few round trips after a packet sent on it went unanswered; one whose
// server sends no FEEDBACK (an older server) is judged by pings only.
func TestFreshUnconfirmed(t *testing.T) {
	aead, _ := chacha20poly1305.New(make([]byte, 32))
	s := &Session{direct: true, relay: &countConn{}, aead: aead, sealer: wrap.NewSealer(aead, wrap.Audio), peer: &net.UDPAddr{}}
	now := time.Now()
	s.LastRx.Store(now.Add(-100 * time.Millisecond).UnixNano())
	s.RTT.Store(int64(20 * time.Millisecond))
	s.touch(now.UnixNano())
	later := now.Add(ackWaitMin + 10*time.Millisecond)
	if !s.Fresh(later) {
		t.Fatal("left out without FEEDBACK from the server")
	}
	s.acks.Store(true)
	if !s.Fresh(now.Add(200 * time.Millisecond)) {
		t.Fatal("left out before the answer was due")
	}
	if s.Fresh(later) {
		t.Fatal("still carrying traffic with nothing confirmed")
	}
	s.LastRx.Store(later.UnixNano())
	if !s.Fresh(later) {
		t.Fatal("not back after an answer")
	}
	// The next packet starts a new wait; the old one does not count.
	s.touch(later.Add(time.Millisecond).UnixNano())
	if !s.Fresh(later.Add(100 * time.Millisecond)) {
		t.Fatal("a new packet judged by the old wait")
	}
}
