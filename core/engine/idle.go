package engine

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/Jetvac/turn-vk-client/core/session"
)

// Idle mode (Config.Power, for phones): a tunnel that has carried next to
// nothing for quietCalm keeps only quietRoutes routes, and they ping
// together, in one burst every session.QuietPing (session/quiet.go). Every
// route is a TURN allocation that pings and refreshes on its own schedule,
// and each packet keeps a phone's radio powered for seconds: 64 of them
// never let it sleep. The first busy seconds (a game, a call, a page)
// bring every route back, a few at a time; the kept ones carry the
// traffic meanwhile.
const (
	quietRoutes = 4
	quietCalm   = 90 * time.Second
	// quietBusy: packets in one second (both ways) that make it busy; two
	// busy seconds in a row, or quietBulk packets in one, end idle mode.
	// A messenger's heartbeat or a notification stays below.
	quietBusy = 30
	quietBulk = 300
	// quietDozeRun: busy seconds in a row that end idle mode while the
	// device dozes (it woke from sleep within dozeWindow): apps sync in
	// Android's maintenance windows for a few seconds, which the kept
	// routes carry; bringing every route back for it costs more.
	quietDozeRun = 5
	// quietRamp: routes come back this far apart (VK sees a ramp).
	quietRamp = 100 * time.Millisecond
	// PowerSaver idles after saverCalm, on saverRoutes routes.
	saverRoutes = 2
	saverCalm   = 30 * time.Second
)

// Routes on demand: a tunnel that carries little keeps lightRoutes routes
// (saverLight in the saver mode), not every one. The stats: every device
// but a downloading PC peaked at 4–8 Mbit/s, about 0.2 Mbit/s a route, and
// spent 76–99 % of its minutes under 2 Mbit/s, while a phone leaving idle
// mode for a notification reopened 28 routes, each a VK allocation, 3–7
// times an hour. heavyRate a second for heavySecs seconds in a row, or
// heavyBulk in one, brings every route back (a download gets full speed a
// few seconds later); after lightCalm with the smoothed rate under
// lightRate the tunnel is light again. PowerAlways and Config.AllRoutes
// keep every route.
const (
	lightRoutes = 12
	saverLight  = 8
	heavyRate   = 3_000_000 / 8 // bytes a second, both ways
	heavyBulk   = 8_000_000 / 8
	heavySecs   = 3
	lightRate   = 1_500_000 / 8
	lightCalm   = 10 * time.Minute
	// lightCalmPC: lightCalm without a power mode (a computer). The
	// stats: computers left the light tier about every two hours, each
	// time asking VK for some 20 allocations (VK credentials 0.26 → 1.9 an
	// hour, error 486 0.1 → 0.5), for little saved: they do not sleep.
	lightCalmPC = 30 * time.Minute
	// rateSmooth: the smoothed rate's time constant, seconds.
	rateSmooth = 30
)

// The power modes (Config.Power), as the user picks them in the app.
const (
	PowerSaver    = "saver"    // idles soon, on 2 routes; Wi-Fi saves power
	PowerBalanced = "balanced" // idles after 90 s, on 4 routes (the default)
	PowerAlways   = "always"   // never idles: every route always ready
)

// idleCalm: how long the tunnel must be calm before it idles.
func (e *Engine) idleCalm() time.Duration {
	if e.cfg.Power == PowerSaver {
		return saverCalm
	}
	return quietCalm
}

// idleKeep: the routes an idle tunnel keeps.
func (e *Engine) idleKeep() int {
	n := quietRoutes
	if e.cfg.Power == PowerSaver {
		n = saverRoutes
	}
	return min(n, e.cfg.Sessions)
}

type idleState struct {
	// cap: routes allowed while idle (0: no limit); secs: seconds spent
	// idle (statistics).
	cap  atomic.Int32
	secs atomic.Uint64

	mu sync.Mutex
	up chan struct{} // closed when idle mode ends: resting slots reopen

	// The watchdog's own.
	prevPk  uint64
	busyAt  time.Time // the last busy second
	busyRun int       // busy seconds in a row

	// Routes on demand, the watchdog's own: the tunnel's bytes at the last
	// tick, the smoothed rate (bytes a second), heavy seconds in a row, and
	// when the tunnel was last busy enough for every route.
	prevBytes uint64
	rate      float64
	heavyRun  int
	heavyAt   time.Time
	// lightSecs: seconds on the light tier (statistics).
	lightSecs atomic.Uint64
}

// lightKeep: the routes a tunnel that carries little keeps; 0: every route.
func (e *Engine) lightKeep() int {
	if e.cfg.AllRoutes || e.cfg.Power == PowerAlways {
		return 0
	}
	n := lightRoutes
	if e.cfg.Power == PowerSaver {
		n = saverLight
	}
	if n >= e.cfg.Sessions {
		return 0
	}
	return n
}

// lightAfter: how long the traffic stays light before the light tier.
func (e *Engine) lightAfter() time.Duration {
	if e.cfg.Power == "" {
		return lightCalmPC
	}
	return lightCalm
}

// light: the light tier holds the routes back now (not idle mode).
func (e *Engine) light() bool {
	k := e.lightKeep()
	return k > 0 && !e.quiet.On() && int(e.idle.cap.Load()) == k
}

// demandTick runs every second of the watchdog: it measures the tunnel's
// traffic and moves between the light tier and every route.
func (e *Engine) demandTick(now time.Time, list []*session.Session) {
	now = now.Round(0)
	by := e.b.bytes.Load()
	d := float64(by - e.idle.prevBytes)
	e.idle.prevBytes = by
	e.idle.rate += (d - e.idle.rate) / rateSmooth
	if d >= heavyRate {
		e.idle.heavyRun++
	} else {
		e.idle.heavyRun = 0
	}
	if d >= heavyRate || e.idle.rate >= lightRate || e.idle.heavyAt.IsZero() {
		e.idle.heavyAt = now
	}
	keep := e.lightKeep()
	if keep == 0 || e.quiet.On() {
		return
	}
	switch c := int(e.idle.cap.Load()); {
	case c == keep:
		e.idle.lightSecs.Add(1)
		if e.idle.heavyRun >= heavySecs || d >= heavyBulk {
			e.openGate(0)
			e.idle.heavyAt = now
			e.logf("busy: back to %d routes", e.limit())
			e.notify()
		}
	case c == 0 && now.Sub(e.idle.heavyAt) >= e.lightAfter() && len(list) > 0 && e.State() == StateConnected:
		if e.shrinkWait(list, keep, now) {
			return
		}
		e.idle.cap.Store(int32(keep))
		for _, s := range list {
			if s.ID >= keep {
				s.Close() // its worker rests until it gets busy
			}
		}
		e.logf("light traffic: %d of %d routes kept, the rest come back when it gets busy", min(keep, len(list)), len(list))
		e.notify()
	}
}

// openGate sets the cap on the routes (0: none) and lets the resting
// slots under it reopen.
func (e *Engine) openGate(c int) {
	e.idle.mu.Lock()
	defer e.idle.mu.Unlock()
	e.idle.cap.Store(int32(c))
	if e.idle.up != nil {
		close(e.idle.up)
	}
	e.idle.up = make(chan struct{})
}

// limit is how many routes the engine keeps now.
func (e *Engine) limit() int {
	n := int(e.target.Load())
	if c := int(e.idle.cap.Load()); c > 0 && c < n {
		return c
	}
	return n
}

// idleUp returns the channel closed when idle mode next ends.
func (e *Engine) idleUp() <-chan struct{} {
	e.idle.mu.Lock()
	defer e.idle.mu.Unlock()
	if e.idle.up == nil {
		e.idle.up = make(chan struct{})
	}
	return e.idle.up
}

// idleStart: the watchdog starts counting.
func (e *Engine) idleStart(now time.Time) {
	e.idle.prevPk = e.b.rx.Load() + e.b.tx.Load()
	e.idle.busyAt = now.Round(0)
	e.idle.busyRun = 0
}

// idleTick runs every second of the watchdog: it enters and leaves idle
// mode, and times the bursts.
func (e *Engine) idleTick(now time.Time, list []*session.Session) {
	if e.quiet == nil {
		return
	}
	// Calm is real time (no monotonic reading): a dozing phone is awake
	// for a moment every half minute, and 90 awake seconds would take it
	// most of an hour.
	now = now.Round(0)
	pk := e.b.rx.Load() + e.b.tx.Load()
	d := pk - e.idle.prevPk
	e.idle.prevPk = pk
	if d >= quietBusy {
		e.idle.busyRun++
		e.idle.busyAt = now
	} else {
		e.idle.busyRun = 0
	}
	if e.quiet.On() {
		e.idle.secs.Add(1)
		run := 2
		if now.UnixNano()-e.wokeAt.Load() < int64(dozeWindow) {
			run = quietDozeRun
		}
		if d >= quietBulk || e.idle.busyRun >= run {
			e.leaveIdle(now)
			return
		}
		if e.quiet.Due(now) {
			e.quiet.Burst(now)
		}
		return
	}
	if now.Sub(e.idle.busyAt) < e.idleCalm() || len(list) == 0 || e.mode.Load() == modeUnknown || e.State() != StateConnected {
		return
	}
	e.enterIdle(now, list)
}

func (e *Engine) enterIdle(now time.Time, list []*session.Session) {
	keep := e.idleKeep()
	if e.shrinkWait(list, keep, now) {
		return
	}
	e.idle.cap.Store(int32(keep))
	if !e.quiet.Enter(now) {
		return
	}
	for _, s := range list {
		if s.ID >= keep {
			s.Close() // its worker rests until idle mode ends
		}
	}
	e.logf("idle: %d of %d routes kept, they ping together every %s (saves battery)", min(keep, len(list)), len(list), session.QuietPing.Round(time.Second))
	e.notify()
}

// shrinkWait tells whether closing the routes over keep (idle mode, the
// light tier) has to wait: the routes kept are those of the first slots,
// and closing now would keep a silent one while closing one that answers,
// or pull routes from under a check of the paths (replaceDeadPaths). The
// stats: a phone went idle in the second five of its twelve routes fell
// silent, kept silent ones, and the check that followed found no route
// answering and rebuilt the whole tunnel. A silent route is replaced or
// answers within seconds; the next tick tries again.
func (e *Engine) shrinkWait(list []*session.Session, keep int, now time.Time) bool {
	if e.probing.Load() {
		return true
	}
	keptSilent, closedAnswers := false, false
	for _, s := range list {
		if s.Closed() {
			continue
		}
		fresh := s.Fresh(now)
		if s.ID < keep && !fresh {
			keptSilent = true
		}
		if s.ID >= keep && fresh {
			closedAnswers = true
		}
	}
	return keptSilent && closedAnswers
}

// leaveIdle: traffic again. The light tier's routes come back; every one
// only if the traffic turns out heavy (demandTick).
func (e *Engine) leaveIdle(now time.Time) {
	e.openGate(e.lightKeep())
	if !e.quiet.Leave(now) {
		return
	}
	e.idle.busyAt = now.Round(0)
	e.logf("traffic again: back to %d routes", e.limit())
	e.notify()
}

// rest holds a slot over the routes allowed now: until idle mode ends
// (then it reopens, after the slots before it), or 30 s (VK's limits are
// checked again). It returns false when the engine stops.
func (e *Engine) rest(i int, up <-chan struct{}) bool {
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	select {
	case <-e.ctx.Done():
		return false
	case <-t.C:
		return true
	case <-up:
		return sleep(e.ctx, time.Duration(max(1, i-quietRoutes+1))*quietRamp)
	}
}
