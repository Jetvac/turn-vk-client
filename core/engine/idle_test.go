package engine

import (
	"testing"
	"time"

	"github.com/Jetvac/turn-vk-client/core/session"
)

func idleEngine(sessions int) *Engine {
	e := &Engine{cfg: Config{Sessions: sessions}, b: newBind(), quiet: session.NewQuiet(), state: StateConnected}
	e.b.quiet = e.quiet
	e.target.Store(int32(sessions))
	e.mode.Store(modeDirect)
	return e
}

func testRoutes(n int) []*session.Session {
	var list []*session.Session
	for i := 0; i < n; i++ {
		s := session.NewTestSession("t")
		s.ID = i
		list = append(list, s)
	}
	return list
}

// A tunnel quiet for quietCalm keeps quietRoutes routes; two busy seconds
// bring them all back; bursts come every QuietPing meanwhile.
func TestIdleMode(t *testing.T) {
	e := idleEngine(16)
	list := testRoutes(8)
	t0 := time.Now()
	e.idleStart(t0)
	at := func(d time.Duration) time.Time { return t0.Add(d) }
	// A heartbeat now and then is no traffic.
	e.b.tx.Add(5)
	e.idleTick(at(quietCalm-time.Second), list)
	if e.quiet.On() {
		t.Fatal("idle before quietCalm")
	}
	e.idleTick(at(quietCalm), list)
	if !e.quiet.On() || e.limit() != quietRoutes {
		t.Fatalf("idle %v, limit %d", e.quiet.On(), e.limit())
	}
	for _, s := range list {
		if s.Closed() != (s.ID >= quietRoutes) {
			t.Fatalf("route %d closed: %v", s.ID, s.Closed())
		}
	}
	if !e.Status().Quiet {
		t.Fatal("status does not tell idle")
	}
	w := e.quiet.Woken()
	e.idleTick(at(quietCalm+session.QuietPing), list[:quietRoutes])
	select {
	case <-w:
	default:
		t.Fatal("no burst after QuietPing")
	}
	// One busy second (a notification) stays idle; two in a row do not.
	up := e.idleUp()
	e.b.rx.Add(quietBusy)
	e.idleTick(at(quietCalm+session.QuietPing+time.Second), list[:quietRoutes])
	if !e.quiet.On() {
		t.Fatal("left idle mode for one busy second")
	}
	e.idleTick(at(quietCalm+session.QuietPing+2*time.Second), list[:quietRoutes])
	e.b.rx.Add(quietBusy)
	e.idleTick(at(quietCalm+session.QuietPing+3*time.Second), list[:quietRoutes])
	e.b.tx.Add(quietBusy)
	e.idleTick(at(quietCalm+session.QuietPing+4*time.Second), list[:quietRoutes])
	if e.quiet.On() || e.limit() != 16 {
		t.Fatalf("still idle after busy seconds: %v, limit %d", e.quiet.On(), e.limit())
	}
	select {
	case <-up:
	default:
		t.Fatal("resting routes not woken")
	}
	// A big burst of packets ends idle mode at once.
	t1 := at(time.Minute)
	e.idleStart(t1)
	e.idleTick(t1.Add(quietCalm), list[:quietRoutes])
	if !e.quiet.On() {
		t.Fatal("not idle again")
	}
	e.b.rx.Add(quietBulk)
	e.idleTick(t1.Add(quietCalm+time.Second), list[:quietRoutes])
	if e.quiet.On() {
		t.Fatal("still idle after a bulk second")
	}
}

// Without Config.Quiet nothing changes; a small set keeps all its routes.
func TestIdleOff(t *testing.T) {
	e := idleEngine(16)
	e.quiet, e.b.quiet = nil, nil
	t0 := time.Now()
	e.idleStart(t0)
	e.idleTick(t0.Add(time.Hour), testRoutes(4))
	if e.quiet.On() || e.limit() != 16 {
		t.Fatal("idle without Config.Quiet")
	}
	e = idleEngine(2)
	e.idleStart(t0)
	list := testRoutes(2)
	e.idleTick(t0.Add(quietCalm), list)
	if !e.quiet.On() || e.limit() != 2 || list[1].Closed() {
		t.Fatal("two routes not both kept")
	}
}
