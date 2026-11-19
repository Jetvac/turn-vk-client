package session

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/Jetvac/turn-vk-client/core/wrap"
)

// While idle a path is judged by the slower rhythm of the bursts, and for
// a while after idle mode ends, until the busy pings have come back.
func TestQuietFresh(t *testing.T) {
	q := NewQuiet()
	now := time.Now()
	s := &Session{direct: true, quiet: q}
	s.LastRx.Store(now.Add(-20 * time.Second).UnixNano())
	if s.Fresh(now) {
		t.Fatal("fresh after 20 s of silence while busy")
	}
	q.Enter(now)
	if !s.Fresh(now) {
		t.Fatal("left out between two idle bursts")
	}
	if s.Fresh(now.Add(QuietPing)) {
		t.Fatal("still fresh after a missed burst")
	}
	q.Leave(now)
	if !s.Fresh(now.Add(quietAfter / 2)) {
		t.Fatal("left out right after idle mode ended")
	}
	if s.Fresh(now.Add(quietAfter + time.Second)) {
		t.Fatal("idle rules kept after idle mode")
	}
	var none *Quiet
	if none.On() || none.Relaxed(now) || none.Nudge(now) || none.Woken() != nil {
		t.Fatal("no idle mode acts")
	}
}

// A packet sent while idle brings the burst forward only when the last
// one was a while ago; bursts come every QuietPing.
func TestQuietNudge(t *testing.T) {
	q := NewQuiet()
	now := time.Now()
	if q.Nudge(now) {
		t.Fatal("burst while busy")
	}
	q.Enter(now)
	if q.Nudge(now.Add(quietNudge / 2)) {
		t.Fatal("burst right after the last")
	}
	w := q.Woken()
	if !q.Nudge(now.Add(quietNudge)) {
		t.Fatal("no burst for a packet long after the last")
	}
	select {
	case <-w:
	default:
		t.Fatal("the burst woke no route")
	}
	at := now.Add(quietNudge)
	if q.Due(at.Add(QuietPing-time.Second)) || !q.Due(at.Add(QuietPing)) {
		t.Fatal("bursts not every QuietPing")
	}
}

type atomicConn struct {
	net.PacketConn
	n atomic.Int32
}

func (c *atomicConn) WriteTo(b []byte, _ net.Addr) (int, error) { c.n.Add(1); return len(b), nil }

// While idle the ping loop pings at each burst (and not on its own
// rhythm); leaving idle mode pings at once.
func TestPingLoopQuiet(t *testing.T) {
	aead, _ := chacha20poly1305.New(make([]byte, 32))
	relay := &atomicConn{}
	q := NewQuiet()
	q.Enter(time.Now())
	s := &Session{direct: true, relay: relay, aead: aead, sealer: wrap.NewSealer(aead, wrap.Audio), peer: &net.UDPAddr{}, quiet: q, done: make(chan struct{})}
	s.LastRx.Store(time.Now().UnixNano())
	go s.pingLoop()
	defer close(s.done)
	waitN := func(n int32) {
		t.Helper()
		for end := time.Now().Add(time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
			if relay.n.Load() >= n {
				return
			}
		}
		t.Fatalf("%d pings, want %d", relay.n.Load(), n)
	}
	time.Sleep(20 * time.Millisecond)
	q.Burst(time.Now())
	waitN(1)
	q.Burst(time.Now())
	waitN(2)
	q.Leave(time.Now())
	waitN(3)
	if got := relay.n.Load(); got != 3 {
		t.Fatalf("%d pings, want 3", got)
	}
}
