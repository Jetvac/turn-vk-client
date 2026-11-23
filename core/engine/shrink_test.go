package engine

import (
	"testing"
	"time"
)

// WireGuard's keepalives get no answer: they are no "sending" for the
// watchdog, which otherwise re-keyed an idle phone every 75 s all night.
func TestKeepaliveAsksNothing(t *testing.T) {
	b := newBind()
	b.sent(make([]byte, wgKeepalive), true)
	b.sent(make([]byte, wgKeepalive), true)
	if b.tx.Load() != 2 || b.asks.Load() != 0 {
		t.Fatalf("keepalives: tx %d, asks %d", b.tx.Load(), b.asks.Load())
	}
	b.sent(make([]byte, 148), true) // a handshake initiation
	b.sent(make([]byte, 96), true)  // data
	b.sent(make([]byte, 96), false) // a copy of it
	if b.tx.Load() != 5 || b.asks.Load() != 2 || b.bytes.Load() != 2*wgKeepalive+148+96 {
		t.Fatalf("tx %d, asks %d, bytes %d", b.tx.Load(), b.asks.Load(), b.bytes.Load())
	}
}

// Going idle waits while a route it would keep is silent and one it would
// close answers, or while the paths are being checked; then it closes the
// routes over the kept ones as before.
func TestIdleKeepsAnsweringRoutes(t *testing.T) {
	e := idleEngine(12)
	list := testRoutes(12)
	at := time.Now()
	for _, s := range list {
		s.LastRx.Store(at.UnixNano())
	}
	list[1].LastRx.Store(at.Add(-time.Hour).UnixNano()) // kept, silent
	e.enterIdle(at, list)
	if e.quiet.On() || e.limit() != 12 {
		t.Fatal("went idle keeping a silent route")
	}
	for _, s := range list {
		if s.Closed() {
			t.Fatalf("route %d closed", s.ID)
		}
	}
	list[1].LastRx.Store(at.UnixNano()) // replaced, or answers again
	e.probing.Store(true)
	e.enterIdle(at, list)
	if e.quiet.On() {
		t.Fatal("went idle during a check of the paths")
	}
	e.probing.Store(false)
	e.enterIdle(at, list)
	if !e.quiet.On() || e.limit() != quietRoutes {
		t.Fatalf("not idle: limit %d", e.limit())
	}
	for _, s := range list {
		if s.Closed() != (s.ID >= quietRoutes) {
			t.Fatalf("route %d closed: %v", s.ID, s.Closed())
		}
	}
	// A silent route among those closed anyway is no reason to wait.
	e = idleEngine(12)
	list = testRoutes(12)
	for _, s := range list {
		s.LastRx.Store(at.UnixNano())
	}
	list[9].LastRx.Store(at.Add(-time.Hour).UnixNano())
	e.enterIdle(at, list)
	if !e.quiet.On() {
		t.Fatal("waited for a route it closes")
	}
}

// The light tier waits the same way.
func TestLightKeepsAnsweringRoutes(t *testing.T) {
	e := demandEngine(32)
	t0 := time.Now()
	tick(e, t0, heavyBulk)
	list := testRoutes(32)
	at := t0.Add(e.lightAfter() + time.Second)
	for _, s := range list {
		s.LastRx.Store(at.UnixNano())
	}
	list[3].LastRx.Store(at.Add(-time.Hour).UnixNano())
	e.idle.rate = 0
	e.demandTick(at, list)
	if e.limit() != 32 {
		t.Fatal("light while a kept route is silent")
	}
	list[3].LastRx.Store(at.UnixNano())
	e.demandTick(at.Add(time.Second), list)
	if e.limit() != lightRoutes {
		t.Fatalf("not light: limit %d", e.limit())
	}
}
