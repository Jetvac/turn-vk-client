package engine

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Jetvac/turn-vk-client/core/session"
)

// pathsEngine: routes on the given servers, silent for a minute: those
// listed in answer answer every probe; the rest none.
func pathsEngine(t *testing.T, servers []string) (*Engine, []*session.Session) {
	t.Helper()
	old := deadProbeWait
	deadProbeWait = 20 * time.Millisecond
	t.Cleanup(func() { deadProbeWait = old })
	e := &Engine{b: newBind(), state: StateConnected}
	e.ctx, e.stop = context.WithCancel(context.Background())
	t.Cleanup(e.stop)
	e.mode.Store(modeDirect)
	var list []*session.Session
	for i, sv := range servers {
		s := session.NewTestSession(sv)
		s.ID = i
		s.LastRx.Store(time.Now().Add(-time.Minute).UnixNano())
		e.b.add(s)
		list = append(list, s)
	}
	return e, list
}

func answers(list ...*session.Session) {
	for _, s := range list {
		s.SetProbe(func(s *session.Session) { s.Answer() })
	}
}

func closedOnes(list []*session.Session) []int {
	var out []int
	for _, s := range list {
		if s.Closed() {
			out = append(out, s.ID)
		}
	}
	return out
}

// A path is replaced only when it misses two probes: one that answers the
// second stays.
func TestDeadPathsNeedTwoMisses(t *testing.T) {
	e, list := pathsEngine(t, []string{"a:1", "a:1", "a:1", "a:1", "b:1", "b:1", "b:1", "b:1"})
	answers(list[:5]...)
	var probes atomic.Int32
	list[5].SetProbe(func(s *session.Session) {
		if probes.Add(1) == 2 {
			s.Answer()
		}
	})
	e.probing.Store(true)
	e.replaceDeadPaths("test", e.b.rx.Load(), list)
	if got := closedOnes(list); len(got) != 2 || got[0] != 6 || got[1] != 7 {
		t.Fatalf("closed %v, want [6 7]", got)
	}
	if d := e.relays.stats["b:1"].drops; d != 2 {
		t.Fatalf("drops on b = %v, want 2", d)
	}
	if e.probing.Load() {
		t.Fatal("probing flag left set")
	}
}

// Every route through one TURN server dead while others answer: the
// server stopped relaying, its routes go, and new ones avoid it.
func TestDeadRelayAvoided(t *testing.T) {
	e, list := pathsEngine(t, []string{"a:1", "a:1", "a:1", "a:1", "b:1", "b:1", "b:1", "b:1"})
	answers(list[:4]...)
	e.probing.Store(true)
	e.replaceDeadPaths("test", e.b.rx.Load(), list)
	if got := closedOnes(list); len(got) != 4 || got[0] != 4 {
		t.Fatalf("closed %v, want the four on b", got)
	}
	if got := e.relays.pick([]string{"a:1", "b:1"}, "b:1", list[:4]); got != "a:1" {
		t.Fatalf("new route on %s", got)
	}
}

// Many dead paths across servers: a quarter of the routes is replaced now,
// the rest are left to their own timeout.
func TestDeadPathsCapped(t *testing.T) {
	var servers []string
	for i := 0; i < 16; i++ {
		servers = append(servers, map[bool]string{true: "a:1", false: "b:1"}[i < 8])
	}
	e, list := pathsEngine(t, servers)
	answers(list[0], list[1], list[8], list[9])
	e.probing.Store(true)
	e.replaceDeadPaths("test", e.b.rx.Load(), list)
	if got := closedOnes(list); len(got) != 4 {
		t.Fatalf("closed %v, want 4 of the 12 dead", got)
	}
}

// No path answers: every one goes (the server is gone or restarted).
func TestNoPathAnswers(t *testing.T) {
	e, list := pathsEngine(t, []string{"a:1", "a:1", "b:1", "b:1"})
	e.probing.Store(true)
	e.replaceDeadPaths("test", e.b.rx.Load(), list)
	if got := closedOnes(list); len(got) != 4 {
		t.Fatalf("closed %v, want all", got)
	}
}

// The handshake warning needs WireGuard to have sent without hearing back:
// an idle tunnel does not re-key and is no fault.
func TestStaleWatch(t *testing.T) {
	var w staleWatch
	if l := w.update(100, 100, time.Minute); l != "" {
		t.Fatalf("fresh: %q", l)
	}
	if l := w.update(100, 300, 10*time.Minute); l != "" {
		t.Fatalf("idle tunnel warned: %q", l)
	}
	if l := w.update(100, 300+staleSent, 10*time.Minute); !strings.Contains(l, "while sending") {
		t.Fatalf("sending without answer: %q", l)
	}
	if l := w.update(200, 300+staleSent, time.Second); l != "WireGuard: the server answers again" {
		t.Fatalf("after a handshake: %q", l)
	}
	if l := w.update(200, 50, 10*time.Minute); l != "" {
		t.Fatalf("counters reset taken for sending: %q", l)
	}
}

// After a sleep keys older than wgRekeyAge are renewed, at most every
// wakeRekeyEvery, and once a route has answered.
func TestWakeRekey(t *testing.T) {
	e := &Engine{}
	e.ctx, e.stop = context.WithCancel(context.Background())
	defer e.stop()
	woke := time.Now()
	if e.wakeRekeyDue(4, woke.Add(-2*time.Minute), woke.UnixNano()) {
		t.Fatal("fresh keys renewed")
	}
	if e.wakeRekeyDue(0, woke.Add(-time.Hour), woke.UnixNano()) {
		t.Fatal("renewed with no route")
	}
	if !e.wakeRekeyDue(4, woke.Add(-wgRekeyAge-time.Second), woke.UnixNano()) {
		t.Fatal("stale keys kept")
	}
	if e.wakeRekeyDue(4, woke.Add(-wgRekeyAge-time.Second), woke.Add(time.Minute).UnixNano()) {
		t.Fatal("renewed again within wakeRekeyEvery")
	}
	if !e.wakeRekeyDue(4, woke.Add(-wgRekeyAge-time.Second), woke.Add(wakeRekeyEvery).UnixNano()) {
		t.Fatal("not renewed after wakeRekeyEvery")
	}

	list := []*session.Session{session.NewTestSession("a:1"), session.NewTestSession("b:1")}
	at := time.Now().UnixNano()
	for _, s := range list {
		s.LastRx.Store(at - int64(time.Minute))
	}
	go func() {
		time.Sleep(150 * time.Millisecond)
		list[1].Answer()
	}()
	done := false
	e.whenAnswered(list, at, 2*time.Second, func() { done = true })
	if !done {
		t.Fatal("not renewed once a route answered")
	}
	done = false
	e.whenAnswered(list[:1], at, 300*time.Millisecond, func() { done = true })
	if done {
		t.Fatal("renewed with no route answering")
	}
}

// New routes lean to the relay where routes die less, while the weaker
// one keeps its weighted share; equal relays change nothing.
func TestRelayPreferReliable(t *testing.T) {
	const weak, solid = "a:1", "b:1"
	var r relays
	r.stats = map[string]*relayStat{
		weak:  {drops: 10, routeSec: 10 * 3600},
		solid: {drops: 1, routeSec: 10 * 3600},
	}
	mk := func(nw, ns int) []*session.Session {
		var l []*session.Session
		for i := 0; i < nw; i++ {
			l = append(l, route(weak))
		}
		for i := 0; i < ns; i++ {
			l = append(l, route(solid))
		}
		return l
	}
	if got := r.pick([]string{weak, solid}, weak, mk(6, 6)); got != solid {
		t.Fatalf("pick = %s, want %s", got, solid)
	}
	if !strings.Contains(r.takeNote(), "lean to TURN server "+solid) || r.takeNote() != "" {
		t.Fatal("no single note for the log")
	}
	// The weaker relay keeps its share (about a fifth here).
	if got := r.pick([]string{weak, solid}, weak, mk(2, 10)); got != weak {
		t.Fatalf("weaker relay starved: %s", got)
	}
	if got := r.pick([]string{weak, solid}, solid, mk(6, 6)); got != solid {
		t.Fatalf("pick = %s", got)
	}
	r.stats[weak].drops = 1
	if got := r.pick([]string{weak, solid}, weak, mk(6, 6)); got != weak {
		t.Fatalf("equal relays: pick = %s", got)
	}
}

// Route time counts while awake and fades by half every relayMemory.
func TestRelayRouteTime(t *testing.T) {
	list := []*session.Session{route("a:1"), route("a:1")}
	var r relays
	t0 := time.Now()
	r.tick(list, t0)
	r.tick(list, t0.Add(time.Second))
	if got := r.stats["a:1"].routeSec; got != 2 {
		t.Fatalf("route time %v, want 2", got)
	}
	r.noteDrop("a:1")
	r.tick(list, t0.Add(time.Second+relayMemory)) // a sleep: no route time
	st := r.stats["a:1"]
	if st.routeSec < 0.99 || st.routeSec > 1.01 || st.drops < 0.49 || st.drops > 0.51 {
		t.Fatalf("after relayMemory: route time %v, drops %v", st.routeSec, st.drops)
	}
}

// Every path answers and nothing came back: the keys are suspected only
// once WireGuard's own keepalive (10 s) could have come; anything from the
// server meanwhile proves them (phones re-keyed hundreds of times at 8-10 s
// of silence, Nov 2026).
func TestRekeyWaitsForKeepalive(t *testing.T) {
	old, oldPoll := keysSuspect, keysPoll
	keysSuspect, keysPoll = 300*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { keysSuspect, keysPoll = old, oldPoll })
	run := func(answerAfter time.Duration) (bool, time.Duration) {
		e, list := pathsEngine(t, []string{"a:1", "a:1", "b:1", "b:1"})
		var rekeyed atomic.Bool
		e.cfg = Config{NoStats: true, Logf: func(f string, a ...any) {
			if strings.Contains(fmt.Sprintf(f, a...), "re-keying") {
				rekeyed.Store(true)
			}
		}}
		answers(list...)
		e.b.sent(make([]byte, wgKeepalive), true) // WireGuard's keepalive wants no answer
		if e.b.waiting(time.Now()) != 0 {
			t.Fatal("a keepalive waits for an answer")
		}
		start := time.Now()
		e.b.sent(make([]byte, 100), true)
		if answerAfter > 0 {
			time.AfterFunc(answerAfter, func() { e.b.deliver(make([]byte, 100)) })
		}
		e.probing.Store(true)
		e.replaceDeadPaths("test", e.b.rx.Load(), list)
		return rekeyed.Load(), time.Since(start)
	}
	if rekeyed, took := run(150 * time.Millisecond); rekeyed || took > 280*time.Millisecond {
		t.Fatalf("the server's keepalive came, yet re-keyed %v after %s", rekeyed, took)
	}
	if rekeyed, took := run(0); !rekeyed || took < keysSuspect {
		t.Fatalf("nothing came back: re-keyed %v after %s, want after %s", rekeyed, took, keysSuspect)
	}
}
