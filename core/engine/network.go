package engine

import (
	"fmt"
	"time"

	"github.com/Jetvac/turn-vk-client/core/session"
)

// The device's network comes and goes: a lift, a tunnel, Wi-Fi that drops
// for a few seconds. Closing the routes then helps nothing: new ones cannot
// open, and VK cannot be told to free the old allocations (the release
// fails with "network is unreachable"), so they stay counted against VK's
// limit and the reconnect after the outage meets error 486 (the stats
// showed 16 of them after one outage). So while there is no network the
// routes are kept; when the same network comes back they are checked, and
// only those that do not answer are replaced.
const (
	// netHold: a route's send failed for lack of network this recently:
	// the device has none.
	netHold = 5 * time.Second
	// switchWait: on a network switch, how long the old routes carry the
	// traffic at most while the new ones open.
	switchWait = 15 * time.Second
)

// netDown tells whether the device has no network now: the platform said
// so, or the sends of half the routes or more just failed for lack of
// one (a single relay out of reach is no outage).
func (e *Engine) netDown(now time.Time) bool {
	if e.netLost.Load() {
		return true
	}
	cut := now.Add(-netHold).UnixNano()
	list := e.b.list()
	n := 0
	for _, s := range list {
		if s.NetErrAt.Load() > cut {
			n++
		}
	}
	return n > 0 && 2*n >= len(list)
}

// holdRoutes logs (once a minute) that dead-looking routes are kept for
// lack of network.
func (e *Engine) holdRoutes(now time.Time) {
	if last := e.heldAt.Load(); now.UnixNano()-last >= int64(time.Minute) && e.heldAt.CompareAndSwap(last, now.UnixNano()) {
		e.logf("no network: the routes are kept until it is back")
	}
}

// NetworkLost: the platform reports the device lost its network.
func (e *Engine) NetworkLost() {
	if e.ctx == nil || e.ctx.Err() != nil || !e.netLost.CompareAndSwap(false, true) {
		return
	}
	e.netLostAt.Store(time.Now().UnixNano())
	e.logf("no network: the routes wait for it")
}

// NetworkBack: the same network is back. The routes are checked rather
// than rebuilt; their TURN state is renewed, since pion's refreshes
// failed meanwhile.
func (e *Engine) NetworkBack() {
	if e.ctx == nil || e.ctx.Err() != nil || !e.netLost.CompareAndSwap(true, false) {
		return
	}
	now := time.Now()
	e.logf("the network is back after %s: checking the routes", now.Sub(time.Unix(0, e.netLostAt.Load())).Round(time.Second))
	e.offline.up()
	e.silent.up()
	// Like a wake from sleep: routes get wakeGrace to answer.
	e.wokeAt.Store(now.UnixNano())
	for _, s := range e.b.list() {
		s.RenewNow()
		go s.Probe()
	}
}

// SwitchNetwork moves the routes to a new network make-before-break: half
// of them are closed (their slots reopen on the new network) while the
// other half, still bound to the old network, carry the traffic; once a
// new route answers, or after switchWait, the rest follow. The platform
// binds each route's socket to the network it opened on (Android), so the
// old ones work for as long as the old network does; where it cannot, the
// old routes are dead anyway and nothing is lost.
func (e *Engine) SwitchNetwork(why string) {
	if e.ctx == nil || e.ctx.Err() != nil {
		return
	}
	e.netLost.Store(false)
	e.offline.up()
	e.silent.up()
	list := e.b.list()
	if len(list) < 2 {
		e.Reconnect(why)
		return
	}
	at := time.Now()
	e.logf("%s: opening routes on the new network before closing the old ones", why)
	for i, s := range list {
		if i%2 == 0 {
			s.Close()
		}
	}
	go e.finishSwitch(at, list)
}

func (e *Engine) finishSwitch(at time.Time, old []*session.Session) {
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	end := time.After(switchWait)
	why := "no new route answered within " + switchWait.String()
wait:
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-end:
			break wait
		case <-t.C:
			if n := newRoutes(e.b.list(), at, time.Now()); n > 0 {
				why = fmt.Sprintf("%d new route(s) answer", n)
				break wait
			}
		}
	}
	left := 0
	for _, s := range old {
		if !s.Closed() {
			s.Close()
			left++
		}
	}
	if left > 0 {
		e.logf("network switch: %s, closing the %d old route(s)", why, left)
	}
}

// newRoutes counts the routes opened after at that answer.
func newRoutes(list []*session.Session, at, now time.Time) int {
	n := 0
	for _, s := range list {
		if s.Started.After(at) && s.Fresh(now) {
			n++
		}
	}
	return n
}
