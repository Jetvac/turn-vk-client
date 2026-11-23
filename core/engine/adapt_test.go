package engine

import (
	"sync"
	"testing"
	"time"

	"github.com/Jetvac/turn-vk-client/core/session"
)

// orderedOut collects what a Reorder hands on.
type orderedOut struct {
	mu  sync.Mutex
	got []uint64
}

func (o *orderedOut) add(v uint64) {
	o.mu.Lock()
	o.got = append(o.got, v)
	o.mu.Unlock()
}

func (o *orderedOut) n() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.got)
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); !ok(); {
		if time.Now().After(end) {
			t.Fatal("timed out waiting for " + what)
		}
		time.Sleep(time.Millisecond)
	}
}

// Gaps that never fill are losses: an adaptive Reorder stops waiting the
// whole hold for them; one that is not adaptive keeps ReorderHold.
func TestReorderHoldShrinksOnLoss(t *testing.T) {
	o := &orderedOut{}
	r := &Reorder[uint64]{Out: o.add, Adapt: true}
	var c uint64
	for i := 0; i < 3*reorderTune; i++ {
		r.Push(1, c, c)
		r.Push(1, c+2, c+2) // c+1 is lost
		want := int(c/3*2) + 2
		waitFor(t, "the gap given up", func() bool { return o.n() == want })
		c += 3
	}
	if h := r.HoldNow(); h != ReorderHoldMin {
		t.Fatalf("hold %v after losses only, want %v", h, ReorderHoldMin)
	}
	plain := &Reorder[uint64]{Out: func(uint64) {}}
	if plain.HoldNow() != ReorderHold {
		t.Fatal("a plain Reorder adapts")
	}
}

// The hold covers how late gap-filling packets come, with a margin, and
// no more than Hold.
func TestReorderHoldFollowsLateness(t *testing.T) {
	r := &Reorder[uint64]{Out: func(uint64) {}, Adapt: true}
	r.mu.Lock()
	for i := 0; i < 2*reorderTune; i++ {
		r.noteLate(4 * time.Millisecond)
	}
	r.mu.Unlock()
	if h, want := r.HoldNow(), 5500*time.Microsecond; h != want {
		t.Fatalf("hold %v for packets 4 ms late, want %v", h, want)
	}
	r.mu.Lock()
	for i := 0; i < reorderSamples; i++ {
		r.noteLate(30 * time.Millisecond)
	}
	r.mu.Unlock()
	if h := r.HoldNow(); h != ReorderHold {
		t.Fatalf("hold %v, want at most %v", h, ReorderHold)
	}
}

// A packet that comes after its gap was given up on counts as late, with
// how long after the wait began; a duplicate of a delivered one does not.
func TestReorderLateAfterGiveUp(t *testing.T) {
	o := &orderedOut{}
	r := &Reorder[uint64]{Out: o.add, Adapt: true}
	r.Push(1, 0, 0)
	r.Push(1, 2, 2)
	waitFor(t, "the gap given up", func() bool { return o.n() == 2 })
	r.Push(1, 1, 1) // late
	r.Push(1, 0, 0) // a duplicate
	r.Push(1, 1, 1) // and of the late one
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.nLate != 1 || r.late[0] < ReorderHold {
		t.Fatalf("late samples %d, first %v", r.nLate, r.late[0])
	}
	if r.Late != 3 {
		t.Fatalf("late or duplicate packets %d, want 3", r.Late)
	}
}

// pick sends a packet the way it would arrive first, a path's losses
// counted: small packets leave a lossy relay for an equal clean one, bulk
// goes there only when the clean one is busier by more than they cost.
func TestPickAvoidsLossyPaths(t *testing.T) {
	b := newBind()
	lossy, clean := session.NewTestSession("lossy"), session.NewTestSession("clean")
	list := []*session.Session{lossy, clean}
	b.setLoss(list, map[string]float64{"lossy": 0.05})
	now := time.Now()
	pick := func(b *bind) *session.Session {
		b.qmu.Lock()
		defer b.qmu.Unlock()
		return b.pick(list, 100, now)
	}
	for i := 0; i < 3; i++ {
		if pick(b) != clean {
			t.Fatalf("small packet %d on the lossy path", i)
		}
	}
	// The clean path's queue: 5 KB, about 29 ms at pathRate, more than
	// the 10 ms the losses cost.
	b.qmu.Lock()
	b.queue(clean).add(now.UnixNano(), 5000)
	b.qmu.Unlock()
	if pick(b) != lossy {
		t.Fatal("the lossy path unused while the clean one is far busier")
	}
	// Loss on every path alike changes nothing: the first of equals.
	b = newBind()
	b.setLoss(list, map[string]float64{"lossy": 0.05, "clean": 0.05})
	if pick(b) != lossy {
		t.Fatal("equal losses changed the choice")
	}
}

// Computers wait longer before the light tier than phones.
func TestLightAfter(t *testing.T) {
	e := idleEngine(32)
	if e.lightAfter() != lightCalmPC {
		t.Fatalf("a computer: %v", e.lightAfter())
	}
	for _, p := range []string{PowerBalanced, PowerSaver} {
		e.cfg.Power = p
		if e.lightAfter() != lightCalm {
			t.Fatalf("%s: %v", p, e.lightAfter())
		}
	}
}
