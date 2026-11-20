package split

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// A program its own rule sends direct (a game, or "games direct") is
// watched as a whole. When its direct UDP gets no answer at all, or one of
// its connections does not open direct while its UDP has not been
// answered yet (it is starting, or looking for a match), the whole program
// goes through the VPN for failTTL: its UDP flows switch at once, its new
// connections follow. A game split between two exits (some connections
// direct, some through the VPN) shows two addresses to its servers, and
// matchmaking or the match does not start; a game blocked direct does not
// start at all. Through the VPN it works, a little farther away. The
// program is listed with the sites that failed direct (Failures), and
// ForgetFailures lets it try direct again.
// appProbeMin, appProbeWait: a program that sent this many direct UDP
// packets over at least this long and got nothing back fails direct.
var (
	appProbeMin  int32 = 20
	appProbeWait       = 8 * time.Second
)

const (
	// appProbeIdle: a program without direct UDP this long is watched
	// afresh.
	appProbeIdle = 5 * time.Minute

	whyAppFailed = "программа не работала напрямую — вся через VPN"
)

// appProbe: a program's direct UDP since it started sending.
type appProbe struct {
	start  int64 // unix ns
	last   atomic.Int64
	sent   atomic.Int32
	ok     atomic.Bool // an answer came
	failed atomic.Bool
}

func appKey(path string) string { return "p:" + strings.ToLower(path) }

// probeFor returns the watch of the program at path.
func (r *Router) probeFor(path string, now int64) *appProbe {
	r.amu.Lock()
	defer r.amu.Unlock()
	p := r.probes[appKey(path)]
	if p == nil || now-p.last.Load() > int64(appProbeIdle) {
		p = &appProbe{start: now}
		p.last.Store(now)
		if r.probes == nil {
			r.probes = map[string]*appProbe{}
		}
		r.probes[appKey(path)] = p
	}
	return p
}

// starting: the program at path sent direct UDP lately and has not had
// an answer yet. A program whose UDP works (a match in play) is not moved
// for a connection that failed: its match would change address.
func (r *Router) starting(path string) bool {
	r.amu.Lock()
	defer r.amu.Unlock()
	p := r.probes[appKey(path)]
	return p != nil && !p.ok.Load() && time.Now().UnixNano()-p.last.Load() < int64(appProbeIdle)
}

// probeSent notes a direct UDP packet of a watched program.
func (r *Router) probeSent(f *flow) {
	p := f.probe
	now := time.Now().UnixNano()
	p.last.Store(now)
	if p.ok.Load() || p.failed.Load() {
		return
	}
	n := p.sent.Add(1)
	if n >= appProbeMin && now-p.start >= int64(appProbeWait) && p.failed.CompareAndSwap(false, true) {
		go r.appFail(f.path, fmt.Sprintf("нет ответа по UDP: %d пакетов за %d с", n, (now-p.start)/int64(time.Second)))
	}
}

// appFailed: the program at path failed direct lately.
func (r *Router) appFailed(path string) bool {
	now := time.Now().UnixMilli()
	r.fmu.Lock()
	defer r.fmu.Unlock()
	x := r.failed[appKey(path)]
	return x != nil && now-x.Last < failTTL.Milliseconds()
}

// appFail sends the program at path through the VPN.
func (r *Router) appFail(path, why string) {
	name := baseName(path)
	r.fmu.Lock()
	if r.failed == nil || len(r.failed) > maxFailures {
		r.failed = map[string]*Failure{}
	}
	x := r.failed[appKey(path)]
	if x == nil {
		x = &Failure{Addr: name} // listed by the program's name
		r.failed[appKey(path)] = x
	}
	x.Why, x.OK, x.Last = why+" — вся программа через VPN", true, time.Now().UnixMilli()
	x.Count++
	r.fmu.Unlock()
	moved := 0
	r.mu.Lock()
	for _, f := range r.flows {
		if f.byApp && f.path == path && f.key.proto == protoUDP && f.route == Direct && !f.reject {
			f.route, f.why = VPN, whyAppFailed
			f.local.Store(false)
			if f.counted {
				f.counted = false
				r.direct.Add(-1)
			}
			moved++
		}
	}
	for k, s := range r.socks {
		if s.proc != nil && s.proc.Path == path {
			delete(r.socks, k)
		}
	}
	r.mu.Unlock()
	r.o.Logf("split: %s does not work direct (%s): all of it goes through the VPN for %s (%d UDP flows moved)", name, why, failTTL, moved)
}

// expireProbes forgets the watches of programs gone quiet.
func (r *Router) expireProbes(now time.Time) {
	r.amu.Lock()
	defer r.amu.Unlock()
	for k, p := range r.probes {
		if now.UnixNano()-p.last.Load() > int64(appProbeIdle) {
			delete(r.probes, k)
		}
	}
}
