package engine

import (
	"fmt"
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
	relayWindow  = 10 * time.Second
	relayMinPkts = 300 // packets a window needs to judge a relay
	// relayStale: windows in a row without enough packets after which a
	// relay's loss no longer counts, and fades. As routes move off a lossy
	// relay, it carries too little to be judged again; its last score
	// would mark it bad for good and drain it route by route (the stats
	// showed 32 moves for one "3.8%" in a night).
	relayStale    = 3
	relayFade     = 0.7
	relayBadLoss  = 0.03 // a relay is worse only above this loss…
	relayBadRatio = 2.0  // …and this many times the best relay's loss
	relayKeep     = 2    // routes left on a worse relay
	relayDownFor  = time.Minute
	// relayLinkLoss: when even the best relay loses this much, the loss is
	// the device's own link (a mobile network), not the relays: moving
	// routes would only cost new allocations.
	relayLinkLoss = 0.02
	// A relay is slow when its routes' round trip is above relaySlowRatio
	// times the best relay's plus relaySlowExtra (after a reconnect routes
	// may land on a relay far slower than the others).
	relaySlowRatio = 2.0
	relaySlowExtra = 50 * time.Millisecond
)

type relayStat struct {
	loss     float64 // smoothed loss fraction
	windows  int     // windows judged
	unjudged int     // windows in a row since the last judged one
	rx, lost uint64  // the current window
	// rtt: the routes' smoothed round trip; rttSum/rttN: the current window.
	rtt        time.Duration
	rttWindows int
	rttSum     time.Duration
	rttN       int
}

type relays struct {
	mu    sync.Mutex
	stats map[string]*relayStat
	prev  map[*session.Session][2]uint64 // counters at the last tick
	start time.Time
	down  map[string]time.Time // relays that failed a new route, until
	// seed: each relay's round trip measured directly (STUN, relayprobe.go)
	// and when; it judges relays until routes on two of them measure
	// their own.
	seed map[string]seedRTT
}

type seedRTT struct {
	rtt time.Duration
	at  time.Time
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
		if d := time.Duration(s.RTT.Load()); d > 0 && s.Fresh(now) {
			st.rttSum += d
			st.rttN++
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
			st.unjudged = 0
		} else if st.unjudged++; st.unjudged >= relayStale {
			st.loss *= relayFade
		}
		st.rx, st.lost = 0, 0
		if st.rttN > 0 {
			w := st.rttSum / time.Duration(st.rttN)
			if st.rttWindows == 0 {
				st.rtt = w
			} else {
				st.rtt = (7*st.rtt + 3*w) / 10
			}
			st.rttWindows++
		}
		st.rttSum, st.rttN = 0, 0
	}
	return true
}

// bad lists the relays clearly worse than the best one: losing more
// packets, or much slower. Loss is not judged when every relay loses
// (the device's own link does).
func (r *relays) bad() map[string]float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	best, known := 1.0, 0
	bestRTT, knownRTT := time.Duration(0), 0
	for _, st := range r.stats {
		if st.windows >= 2 && st.unjudged < relayStale {
			best = min(best, st.loss)
			known++
		}
		if st.rttWindows >= 2 {
			if knownRTT == 0 || st.rtt < bestRTT {
				bestRTT = st.rtt
			}
			knownRTT++
		}
	}
	out := map[string]float64{}
	if known >= 2 && best < relayLinkLoss {
		for k, st := range r.stats {
			if st.windows >= 2 && st.unjudged < relayStale && st.loss > relayBadLoss && st.loss > relayBadRatio*best+0.01 {
				out[k] = st.loss
			}
		}
	}
	if knownRTT >= 2 {
		slow := time.Duration(relaySlowRatio*float64(bestRTT)) + relaySlowExtra
		for k, st := range r.stats {
			if st.rttWindows >= 2 && st.rtt > slow {
				if _, ok := out[k]; !ok {
					out[k] = st.loss
				}
			}
		}
	} else {
		// Routes measure the round trip through the relay to the server,
		// a direct probe only to the relay: the two are not compared.
		for k := range r.slowSeeds(time.Now()) {
			if _, ok := out[k]; !ok {
				out[k] = 0
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// seedFor: probes older than this no longer judge (the network changes).
const seedFor = 30 * time.Minute

// noteSeed records a relay's directly measured round trip.
func (r *relays) noteSeed(server string, rtt time.Duration, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seed == nil {
		r.seed = map[string]seedRTT{}
	}
	r.seed[server] = seedRTT{rtt, now}
}

// seeded tells whether server was probed lately.
func (r *relays) seeded(server string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	sd, ok := r.seed[server]
	return ok && now.Sub(sd.at) < seedFor
}

// slowSeeds: the relays whose probe was much slower than the fastest's
// (two probed lately at least). Called with r.mu held.
func (r *relays) slowSeeds(now time.Time) map[string]time.Duration {
	best, n := time.Duration(0), 0
	for _, sd := range r.seed {
		if now.Sub(sd.at) < seedFor {
			if n == 0 || sd.rtt < best {
				best = sd.rtt
			}
			n++
		}
	}
	if n < 2 {
		return nil
	}
	slow := time.Duration(relaySlowRatio*float64(best)) + relaySlowExtra
	out := map[string]time.Duration{}
	for k, sd := range r.seed {
		if now.Sub(sd.at) < seedFor && sd.rtt > slow {
			out[k] = best
		}
	}
	return out
}

// why tells why a relay is judged worse, for the log.
func (r *relays) why(server string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.stats[server]
	if best, ok := r.slowSeeds(time.Now())[server]; ok {
		if sd := r.seed[server]; st == nil || st.rttWindows < 2 {
			return fmt.Sprintf("answered a probe in %d ms (the best in %d ms)", sd.rtt.Milliseconds(), best.Milliseconds())
		}
	}
	if st == nil {
		return "is worse"
	}
	bestRTT := time.Duration(0)
	for _, o := range r.stats {
		if o.rttWindows >= 2 && (bestRTT == 0 || o.rtt < bestRTT) {
			bestRTT = o.rtt
		}
	}
	if st.rttWindows >= 2 && bestRTT > 0 && st.rtt > time.Duration(relaySlowRatio*float64(bestRTT))+relaySlowExtra {
		return fmt.Sprintf("answers in %d ms (the best in %d ms)", st.rtt.Milliseconds(), bestRTT.Milliseconds())
	}
	return fmt.Sprintf("loses %.1f%% of the packets", 100*st.loss)
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
