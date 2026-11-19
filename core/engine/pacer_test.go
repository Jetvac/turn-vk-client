package engine

import (
	"testing"
	"time"

	"github.com/Jetvac/turn-vk-client/core/session"
)

// pacedSession is a session whose server has sent FEEDBACK.
func pacedSession(rtt time.Duration) *session.Session {
	s := &session.Session{}
	s.RTT.Store(int64(rtt))
	s.Pace.OnFeedback(make([]byte, 14), time.Now().UnixNano())
	return s
}

func TestPacerStep(t *testing.T) {
	b := newBind()
	fast, slow := pacedSession(50*time.Millisecond), pacedSession(90*time.Millisecond)
	b.add(slow)
	b.add(fast)
	if !b.paced(b.list(), time.Now()) {
		t.Fatal("sessions with FEEDBACK not paced")
	}
	p := b.pacer
	p.mu.Lock()
	p.running = true // no goroutine: step by hand
	p.mu.Unlock()

	small := make([]byte, 100)
	big := make([]byte, 1300)
	p.enqueue([][]byte{big, small})
	out, _ := p.step(nil)
	// The small packet first, on both sessions (fastest first), then the big one.
	if len(out) != 3 || out[0].s != fast || out[1].s != slow || !out[1].dup || len(out[2].b) != 1300 {
		t.Fatalf("plan: %+v", out)
	}

	// A burst: what the tokens allow now, the rest after a wait.
	var burst [][]byte
	for i := 0; i < 60; i++ {
		burst = append(burst, big)
	}
	p.enqueue(burst)
	out, wait := p.step(nil)
	if len(out) == 0 || len(out) >= 60 || wait <= 0 || wait > 50*time.Millisecond {
		t.Fatalf("burst: %d sent now, wait %v", len(out), wait)
	}

	// Waiting longer than maxQueueDelay drops bulk.
	p.mu.Lock()
	for i := range p.lo {
		p.lo[i].at -= int64(time.Second)
	}
	p.mu.Unlock()
	p.step(nil)
	if p.dropped.Load() == 0 || len(p.lo) != 0 {
		t.Fatalf("old bulk kept: %d queued, %d dropped", len(p.lo), p.dropped.Load())
	}
}

func TestNotPacedWithoutFeedback(t *testing.T) {
	b := newBind()
	b.add(&session.Session{})
	if b.paced(b.list(), time.Now()) {
		t.Fatal("paced although the server sends no FEEDBACK")
	}
}

// An idle path with the shorter round trip carries small packets even when
// the other one is paced at a lower rate (the spare tokens of a slow path
// are no reason to prefer it).
func TestPacerPickShortestIdle(t *testing.T) {
	fast, slow := pacedSession(20*time.Millisecond), pacedSession(40*time.Millisecond)
	slow.Pace.Seed(60_000)
	fast.Pace.Seed(400_000)
	now := time.Now().UnixNano()
	fast.Pace.Refill(now)
	slow.Pace.Refill(now)
	p := &pacer{}
	if got := p.pick([]*session.Session{slow, fast}, 100, nil, false); got != fast {
		t.Fatal("small packet not on the path with the shorter round trip")
	}
}

// The copy of a small packet goes through another VK TURN server, even
// when a path on the same one has the shorter round trip.
func TestPacerCopyOtherRelay(t *testing.T) {
	a1, a2, b := pacedSession(10*time.Millisecond), pacedSession(12*time.Millisecond), pacedSession(30*time.Millisecond)
	a1.Server, a2.Server, b.Server = "1.1.1.1:19302", "1.1.1.1:19302", "2.2.2.2:19302"
	now := time.Now().UnixNano()
	list := []*session.Session{a1, a2, b}
	for _, s := range list {
		s.Pace.Refill(now)
	}
	p := &pacer{}
	first := p.pick(list, 100, nil, false)
	if first != a1 {
		t.Fatal("first copy not on the shortest path")
	}
	if got := p.pickCopy(list, 100, first); got != b {
		t.Fatal("second copy not through the other relay")
	}
	// Only one relay: any other path.
	if got := p.pickCopy(list[:2], 100, a1); got != a2 {
		t.Fatal("no copy with a single relay")
	}
}
