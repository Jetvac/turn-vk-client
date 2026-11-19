package engine

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/Jetvac/turn-vk-client/core/session"
)

// Idle mode (Config.Quiet, for phones): a tunnel that has carried next to
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
	// quietRamp: routes come back this far apart (VK sees a ramp).
	quietRamp = 100 * time.Millisecond
)

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
	e.idle.busyAt = now
	e.idle.busyRun = 0
}

// idleTick runs every second of the watchdog: it enters and leaves idle
// mode, and times the bursts.
func (e *Engine) idleTick(now time.Time, list []*session.Session) {
	if e.quiet == nil {
		return
	}
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
		if d >= quietBulk || e.idle.busyRun >= 2 {
			e.leaveIdle(now)
			return
		}
		if e.quiet.Due(now) {
			e.quiet.Burst(now)
		}
		return
	}
	if now.Sub(e.idle.busyAt) < quietCalm || len(list) == 0 || e.mode.Load() == modeUnknown || e.State() != StateConnected {
		return
	}
	e.enterIdle(now, list)
}

func (e *Engine) enterIdle(now time.Time, list []*session.Session) {
	keep := min(quietRoutes, e.cfg.Sessions)
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

func (e *Engine) leaveIdle(now time.Time) {
	e.idle.mu.Lock()
	e.idle.cap.Store(0)
	if e.idle.up != nil {
		close(e.idle.up)
	}
	e.idle.up = make(chan struct{})
	e.idle.mu.Unlock()
	if !e.quiet.Leave(now) {
		return
	}
	e.idle.busyAt = now
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
