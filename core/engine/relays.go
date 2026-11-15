package engine

import (
	"sync"
	"time"

	"github.com/Jetvac/turn-vk-client/core/session"
)

// VK hands out several TURN servers (relays) per call, and they are not
// equal: measured from one server, routes through one relay lost 2–14 %
// of the server's packets, through the other 0–1 %, and carried 3–5 times
// less. The engine therefore scores the relays by the loss its routes see
// (the server's packets they miss) and steers routes away from one that is
// clearly worse: new routes avoid it, and its routes are moved one at a
// time. A couple stay on it, so that it is still measured and the tunnel
// does not hang on a single relay.
const (
	relayWindow   = 10 * time.Second
	relayMinPkts  = 300  // packets a window needs to judge a relay
	relayBadLoss  = 0.03 // a relay is worse only above this loss…
	relayBadRatio = 2.0  // …and this many times the best relay's loss
	relayKeep     = 2    // routes left on a worse relay
	relayDownFor  = time.Minute
)

type relayStat struct {
	loss     float64 // smoothed loss fraction
	windows  int     // windows judged
	rx, lost uint64  // the current window
}

type relays struct {
	mu    sync.Mutex
	stats map[string]*relayStat
	prev  map[*session.Session][2]uint64 // counters at the last tick
	start time.Time
	down  map[string]time.Time // relays that failed a new route, until
}

// failed notes that a new route through server failed (no allocation, no
// answer): new routes avoid it for relayDownFor.
func (r *relays) failed(server string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.down == nil {
		r.down = map[string]time.Time{}
	}
	r.down[server] = now.Add(relayDownFor)
}

// tick adds what the routes received since the last tick; once a window
// is full it updates the scores and returns true.
func (r *relays) tick(list []*session.Session, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stats == nil {
		r.stats, r.prev, r.start = map[string]*relayStat{}, map[*session.Session][2]uint64{}, now
	}
	seen := make(map[*session.Session]bool, len(list))
	for _, s := range list {
		if !s.Direct() {
			continue
		}
		seen[s] = true
		rx, lost := s.RxPackets.Load(), s.RxLost.Load()
		p := r.prev[s]
		r.prev[s] = [2]uint64{rx, lost}
		st := r.stats[s.Server]
		if st == nil {
			st = &relayStat{}
			r.stats[s.Server] = st
		}
		if rx >= p[0] && lost >= p[1] {
			st.rx += rx - p[0]
			st.lost += lost - p[1]
		}
	}
	for s := range r.prev {
		if !seen[s] {
			delete(r.prev, s)
		}
	}
	if now.Sub(r.start) < relayWindow {
		return false
	}
	r.start = now
	for _, st := range r.stats {
		if n := st.rx + st.lost; n >= relayMinPkts {
			w := float64(st.lost) / float64(n)
			if st.windows == 0 {
				st.loss = w
			} else {
				st.loss = 0.7*st.loss + 0.3*w
			}
			st.windows++
		}
		st.rx, st.lost = 0, 0
	}
	return true
}

// bad lists the relays clearly worse than the best one.
func (r *relays) bad() map[string]float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	best, known := 1.0, 0
	for _, st := range r.stats {
		if st.windows >= 2 {
			best = min(best, st.loss)
			known++
		}
	}
	if known < 2 {
		return nil
	}
	out := map[string]float64{}
	for k, st := range r.stats {
		if st.windows >= 2 && st.loss > relayBadLoss && st.loss > relayBadRatio*best+0.01 {
			out[k] = st.loss
		}
	}
	return out
}

func (r *relays) lossOf(server string) float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st := r.stats[server]; st != nil {
		return st.loss
	}
	return 0
}

// pick chooses the relay for a new route: the usual rotation, unless that
// relay is worse than another or failed lately; then the good relay with
// the fewest routes.
func (r *relays) pick(servers []string, def string, list []*session.Session) string {
	if len(servers) < 2 {
		return def
	}
	bad := r.bad()
	now := time.Now()
	r.mu.Lock()
	for k, until := range r.down {
		if now.Before(until) {
			if bad == nil {
				bad = map[string]float64{}
			}
			bad[k] = 1
		} else {
			delete(r.down, k)
		}
	}
	r.mu.Unlock()
	if len(bad) == 0 {
		return def
	}
	if _, isBad := bad[def]; !isBad {
		return def
	}
	count := map[string]int{}
	for _, s := range list {
		count[s.Server]++
	}
	best := ""
	for _, sv := range servers {
		if _, isBad := bad[sv]; isBad {
			continue
		}
		if best == "" || count[sv] < count[best] {
			best = sv
		}
	}
	if best == "" {
		return def
	}
	return best
}

// moveOne returns a route on a worse relay to close (its worker reopens
// it on a better one), or nil. relayKeep routes stay on each relay.
func (r *relays) moveOne(list []*session.Session) *session.Session {
	bad := r.bad()
	if len(bad) == 0 {
		return nil
	}
	count := map[string]int{}
	good := false
	for _, s := range list {
		count[s.Server]++
		if _, isBad := bad[s.Server]; !isBad {
			good = true
		}
	}
	if !good {
		return nil
	}
	var worst *session.Session
	for _, s := range list {
		if _, isBad := bad[s.Server]; !isBad || count[s.Server] <= relayKeep || !s.Direct() {
			continue
		}
		// The route that carried the least: the one the server already
		// trusts least.
		if worst == nil || s.RxPackets.Load() < worst.RxPackets.Load() {
			worst = s
		}
	}
	return worst
}
