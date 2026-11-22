package engine

import (
	"testing"
	"time"
)

// demandEngine: a desktop's tunnel (no idle mode) on the light tier, as
// Start leaves it.
func demandEngine(sessions int) *Engine {
	e := idleEngine(sessions)
	e.quiet, e.b.quiet = nil, nil
	if k := e.lightKeep(); k > 0 {
		e.idle.cap.Store(int32(k))
	}
	return e
}

// tick runs one watchdog second that carried n bytes.
func tick(e *Engine, at time.Time, n uint64) {
	e.b.bytes.Add(n)
	e.demandTick(at, testRoutes(e.limit()))
}

// A tunnel that carries little keeps the light tier; three heavy seconds
// in a row, or one bulk second, bring every route; one heavy second does
// not.
func TestRoutesOnDemand(t *testing.T) {
	e := demandEngine(32)
	t0 := time.Now()
	if e.limit() != lightRoutes || !e.Status().Light {
		t.Fatalf("limit %d, light %v", e.limit(), e.Status().Light)
	}
	tick(e, t0, heavyRate)
	tick(e, t0.Add(time.Second), 1000)
	tick(e, t0.Add(2*time.Second), heavyRate)
	tick(e, t0.Add(3*time.Second), heavyRate)
	if e.limit() != lightRoutes {
		t.Fatal("full tier for two heavy seconds")
	}
	up := e.idleUp()
	tick(e, t0.Add(4*time.Second), heavyRate)
	if e.limit() != 32 || e.Status().Light {
		t.Fatalf("heavy traffic: limit %d", e.limit())
	}
	select {
	case <-up:
	default:
		t.Fatal("resting routes not woken")
	}

	e = demandEngine(32)
	tick(e, t0, heavyBulk)
	if e.limit() != 32 {
		t.Fatal("a bulk second did not bring every route")
	}
	if e.idle.lightSecs.Load() != 1 {
		t.Fatalf("light seconds %d", e.idle.lightSecs.Load())
	}
}

// After lightCalm without much traffic the tunnel is light again: the
// routes over the light tier close (their workers rest).
func TestRoutesBackToLight(t *testing.T) {
	e := demandEngine(32)
	t0 := time.Now()
	tick(e, t0, heavyBulk)
	list := testRoutes(32)
	e.demandTick(t0.Add(lightCalm/2), list)
	if e.limit() != 32 {
		t.Fatal("light again before lightCalm")
	}
	e.idle.rate = 0 // the download long over
	e.demandTick(t0.Add(lightCalm+time.Second), list)
	if e.limit() != lightRoutes || !e.Status().Light {
		t.Fatalf("not light after lightCalm: limit %d", e.limit())
	}
	for _, s := range list {
		if s.Closed() != (s.ID >= lightRoutes) {
			t.Fatalf("route %d closed: %v", s.ID, s.Closed())
		}
	}
	// Steady moderate traffic (the smoothed rate over lightRate) keeps
	// every route.
	e = demandEngine(32)
	tick(e, t0, heavyBulk)
	for s := 1; s <= int(lightCalm/time.Second)+5; s += 10 {
		e.idle.rate = 2 * lightRate
		e.demandTick(t0.Add(time.Duration(s)*time.Second), list[:lightRoutes])
	}
	if e.limit() != 32 {
		t.Fatal("light while the traffic went on")
	}
}

// Power "always", Config.AllRoutes and a small set keep every route; the
// saver mode keeps fewer when light.
func TestRoutesOnDemandModes(t *testing.T) {
	for _, c := range []struct {
		power string
		all   bool
		n     int
		keep  int
	}{
		{"", false, 32, lightRoutes},
		{PowerBalanced, false, 32, lightRoutes},
		{PowerSaver, false, 32, saverLight},
		{PowerAlways, false, 32, 0},
		{"", true, 32, 0},
		{"", false, lightRoutes, 0},
	} {
		e := idleEngine(c.n)
		e.cfg.Power, e.cfg.AllRoutes = c.power, c.all
		if got := e.lightKeep(); got != c.keep {
			t.Errorf("%q all=%v %d routes: light keeps %d, want %d", c.power, c.all, c.n, got, c.keep)
		}
	}
	e := demandEngine(32)
	e.cfg.AllRoutes = true
	e.idle.cap.Store(0)
	e.demandTick(time.Now().Add(time.Hour), testRoutes(32))
	if e.limit() != 32 || e.Status().Light {
		t.Fatal("AllRoutes went light")
	}
}

// A phone leaving idle mode for a notification gets the light tier only;
// a download right after brings every route.
func TestIdleToLightToFull(t *testing.T) {
	e := idleEngine(32)
	e.cfg.Power = PowerBalanced
	list := testRoutes(lightRoutes)
	t0 := time.Now()
	e.idleStart(t0)
	e.idleTick(t0.Add(quietCalm), list)
	if !e.quiet.On() {
		t.Fatal("not idle")
	}
	e.b.rx.Add(quietBulk)
	e.idleTick(t0.Add(quietCalm+time.Second), list[:quietRoutes])
	if e.quiet.On() || e.limit() != lightRoutes {
		t.Fatalf("after idle: limit %d", e.limit())
	}
	e.b.bytes.Add(heavyBulk)
	e.demandTick(t0.Add(quietCalm+2*time.Second), list)
	if e.limit() != 32 {
		t.Fatalf("download after idle: limit %d", e.limit())
	}
}
