package session

import (
	"sync"
	"sync/atomic"
	"time"
)

// Quiet is the idle mode, for phones: while the tunnel carries next to
// nothing, the routes ping together, in one burst every QuietPing, instead
// of each on its own every pingInterval. A phone's radio stays powered
// for several seconds after each packet, so pings spread over time keep it
// awake for good; bursts let it sleep in between. Paths are judged by
// that slower rhythm while idle and for a while after.
type Quiet struct {
	on      atomic.Bool
	until   atomic.Int64 // unix ns: the idle rules still apply until then
	burstAt atomic.Int64 // unix ns of the last burst

	mu   sync.Mutex
	wake chan struct{} // closed by each burst
}

const (
	// QuietPing: how often the idle routes ping. Under the 30 s that
	// mobile networks keep an idle UDP mapping open (as WireGuard's 25 s
	// keepalive), so the TURN allocations stay reachable.
	QuietPing = 25 * time.Second
	// quietFresh: an idle path heard from within this carries traffic
	// (a burst, plus PathFresh); quietDead: one silent this long (two
	// bursts missed) is replaced.
	quietFresh = QuietPing + PathFresh
	quietDead  = 2*QuietPing + 10*time.Second
	// quietNudge: a packet sent while idle brings the next burst forward
	// when the last was this long ago, so that the radio wakes once for
	// both (WireGuard's keepalive, a messenger's heartbeat).
	quietNudge = 10 * time.Second
	// quietAfter: after leaving idle mode, paths are judged by the idle
	// rules until the pings of the busy rhythm have come back.
	quietAfter = PathFresh
)

// NewQuiet returns the idle mode, off.
func NewQuiet() *Quiet { return &Quiet{wake: make(chan struct{})} }

// On tells whether the routes are idle.
func (q *Quiet) On() bool { return q != nil && q.on.Load() }

// Enter starts idle mode; it reports whether it was off.
func (q *Quiet) Enter(now time.Time) bool {
	if q == nil || !q.on.CompareAndSwap(false, true) {
		return false
	}
	q.burstAt.Store(now.UnixNano())
	return true
}

// Leave ends idle mode and pings every route at once; it reports whether
// it was on.
func (q *Quiet) Leave(now time.Time) bool {
	if q == nil || !q.on.CompareAndSwap(true, false) {
		return false
	}
	q.until.Store(now.Add(quietAfter).UnixNano())
	q.Burst(now)
	return true
}

// Burst has every route ping now.
func (q *Quiet) Burst(now time.Time) {
	if q == nil {
		return
	}
	q.burstAt.Store(now.UnixNano())
	q.mu.Lock()
	close(q.wake)
	q.wake = make(chan struct{})
	q.mu.Unlock()
}

// Due tells whether the next idle burst is due.
func (q *Quiet) Due(now time.Time) bool {
	return q.On() && now.UnixNano()-q.burstAt.Load() >= int64(QuietPing)
}

// Nudge: a packet goes out while idle. The burst comes now if the last
// was quietNudge ago or more (the radio is awake for this packet anyway);
// it reports whether it did.
func (q *Quiet) Nudge(now time.Time) bool {
	if !q.On() {
		return false
	}
	b := q.burstAt.Load()
	if now.UnixNano()-b < int64(quietNudge) || !q.burstAt.CompareAndSwap(b, now.UnixNano()) {
		return false
	}
	q.Burst(now)
	return true
}

// woken returns the channel the next burst closes.
func (q *Quiet) woken() <-chan struct{} {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.wake
}

// relaxed tells whether paths are judged by the idle rules at now (ns).
func (q *Quiet) relaxed(now int64) bool {
	return q != nil && (q.on.Load() || now < q.until.Load())
}

// freshFor and deadAfter: how long a path may be silent and still carry
// traffic, or be kept.
func (q *Quiet) freshFor(now int64) int64 {
	if q.relaxed(now) {
		return int64(quietFresh)
	}
	return int64(PathFresh)
}

func (q *Quiet) deadAfter(now int64) int64 {
	if q.relaxed(now) {
		return int64(quietDead)
	}
	return int64(pathDead)
}

// Relaxed tells whether paths are judged by the idle rules now (idle, or
// just after).
func (q *Quiet) Relaxed(now time.Time) bool { return q.relaxed(now.UnixNano()) }

// Woken returns the channel the next burst closes (nil without idle mode).
func (q *Quiet) Woken() <-chan struct{} { return q.woken() }
