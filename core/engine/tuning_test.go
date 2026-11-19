package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Jetvac/turn-vk-client/core/link"
	"github.com/Jetvac/turn-vk-client/core/session"
	"github.com/Jetvac/turn-vk-client/core/vkcreds"
)

// scoreWindows feeds three windows of traffic: loss per relay, and the
// routes' round trip.
func scoreWindows(t *testing.T, r *relays, list []*session.Session, loss map[string]int, rtt map[string]time.Duration) {
	t.Helper()
	now := time.Now()
	r.tick(list, now)
	for w := 1; w <= 3; w++ {
		at := now.Add(time.Duration(w) * relayWindow)
		for _, s := range list {
			s.LastRx.Store(at.UnixNano())
			s.RxPackets.Add(uint64(1000 - loss[s.Server]))
			s.RxLost.Add(uint64(loss[s.Server]))
			s.RTT.Store(int64(rtt[s.Server]))
		}
		if !r.tick(list, at) {
			t.Fatalf("window %d not closed", w)
		}
	}
}

// On a lossy link (a mobile network) every relay loses: no relay is
// judged worse by loss, so no route moves.
func TestRelayLossyLink(t *testing.T) {
	const a, b = "a:1", "b:1"
	var list []*session.Session
	for i := 0; i < 8; i++ {
		list = append(list, route(a), route(b))
	}
	var r relays
	scoreWindows(t, &r, list, map[string]int{a: 50, b: 200}, map[string]time.Duration{a: 40 * time.Millisecond, b: 45 * time.Millisecond})
	if bad := r.bad(); len(bad) != 0 {
		t.Fatalf("lossy link judged: %v", bad)
	}
	if r.moveOne(list) != nil {
		t.Fatal("moved a route on a lossy link")
	}
}

// A relay much slower than the other is worse, whatever its loss.
func TestRelaySlow(t *testing.T) {
	const fast, slow = "fast:1", "slow:1"
	var list []*session.Session
	for i := 0; i < 6; i++ {
		list = append(list, route(fast), route(slow))
	}
	var r relays
	scoreWindows(t, &r, list, map[string]int{}, map[string]time.Duration{fast: 40 * time.Millisecond, slow: 600 * time.Millisecond})
	bad := r.bad()
	if _, ok := bad[slow]; !ok || len(bad) != 1 {
		t.Fatalf("bad = %v, want only %s", bad, slow)
	}
	if !strings.Contains(r.why(slow), "600 ms") {
		t.Fatalf("why = %q", r.why(slow))
	}
	if got := r.pick([]string{fast, slow}, slow, list); got != fast {
		t.Fatalf("pick = %s, want %s", got, fast)
	}
	if s := r.moveOne(list); s == nil || s.Server != slow {
		t.Fatalf("moveOne = %v", s)
	}
	// A little slower is not worse.
	var r2 relays
	list = nil
	for i := 0; i < 6; i++ {
		list = append(list, route(fast), route(slow))
	}
	scoreWindows(t, &r2, list, map[string]int{}, map[string]time.Duration{fast: 40 * time.Millisecond, slow: 90 * time.Millisecond})
	if bad := r2.bad(); len(bad) != 0 {
		t.Fatalf("judged a slightly slower relay: %v", bad)
	}
}

func testEngine(t *testing.T, sessions int) *Engine {
	t.Helper()
	e, err := New(Config{Link: link.Link{Host: "127.0.0.1", WGPort: 1, Password: "p", Hashes: []string{"hash"}}, DeviceID: "d", Sessions: sessions, NoStats: true, VKCache: t.TempDir() + "/vk.json"})
	if err != nil {
		t.Fatal(err)
	}
	e.ctx = context.Background()
	return e
}

// Error 486: a group moves to a free guest that has not hit the limit
// lately; with none left it keeps its credentials and waits, longer each
// time, and the engine uses fewer routes.
func TestQuotaGuests(t *testing.T) {
	e := testEngine(t, 64)
	hs := e.hashes[0]
	now := time.Now()
	for g := 0; g < 8; g++ {
		hs.slot(g) // guests 0..3, two groups each
	}
	c := &vkcreds.Creds{Username: "u", Servers: []string{"1.2.3.4:3478"}, Fetched: now, Expires: now.Add(time.Hour)}
	hs.slot(0).cur.Store(c)
	n, moved := hs.nextGuest(0, c, now)
	if !moved || n != 4 {
		t.Fatalf("moved to %d (%v), want guest 4", n, moved)
	}
	if hs.slot(0).cur.Load() != nil {
		t.Fatal("the refused credentials were kept")
	}
	// Guests 4..7 taken or full, 0 full: nowhere to go.
	for _, g := range []int{2, 4, 6} {
		c := &vkcreds.Creds{Username: "u"}
		hs.slot(g).cur.Store(c)
		hs.nextGuest(g, c, now)
	}
	c7 := &vkcreds.Creds{Username: "u"}
	hs.slot(7).cur.Store(c7)
	if _, moved := hs.nextGuest(7, c7, now); moved {
		t.Fatalf("moved with no free guest: guests %v", guests(hs))
	}
	if hs.slot(7).cur.Load() != c7 {
		t.Fatal("credentials dropped with nowhere to move")
	}
	// A free guest that hit the limit lately is not moved to until it rests.
	e2 := testEngine(t, 16)
	h2 := e2.hashes[0]
	h2.slot(0)
	h2.slot(1)
	h2.full = map[int32]time.Time{}
	for k := int32(1); k < maxGuests; k++ {
		h2.full[k] = now
	}
	c0 := &vkcreds.Creds{Username: "u"}
	h2.slot(0).cur.Store(c0)
	if _, moved := h2.nextGuest(0, c0, now); moved {
		t.Fatal("moved to a guest that just hit the limit")
	}
	if n, moved := h2.nextGuest(0, c0, now.Add(guestRest+time.Second)); !moved || n != 1 {
		t.Fatalf("after the rest: %d %v", n, moved)
	}

	w1, first := hs.quotaBackoff(1, now)
	if !first || w1 != quotaWait {
		t.Fatalf("first wait %s %v", w1, first)
	}
	if _, first := hs.quotaBackoff(1, now.Add(time.Second)); first {
		t.Fatal("a second 486 during the wait restarted it")
	}
	if _, err := hs.get(context.Background(), e, 1); !errors.As(err, new(*waitError)) {
		t.Fatalf("get during the wait: %v", err)
	}
	if w2, _ := hs.quotaBackoff(1, now.Add(w1+time.Second)); w2 != 2*quotaWait {
		t.Fatalf("second wait %s", w2)
	}

	e.lowerTarget(now)
	if e.target.Load() != 56 {
		t.Fatalf("target %d", e.target.Load())
	}
	e.lowerTarget(now.Add(time.Second))
	if e.target.Load() != 56 {
		t.Fatal("lowered twice within quotaWait")
	}
	for k := 1; k <= 10; k++ {
		e.lowerTarget(now.Add(time.Duration(k) * 2 * quotaWait))
	}
	if e.target.Load() != 32 {
		t.Fatalf("target %d, want the floor 32", e.target.Load())
	}
	e.quotaAt.Store(now.UnixNano())
	late := now.Add(30 * quotaWait)
	e.raiseTarget(late.Add(-targetRestore + time.Minute))
	if e.target.Load() != 32 {
		t.Fatal("raised soon after a 486")
	}
	e.raiseTarget(late.Add(targetRestore))
	if e.target.Load() != 40 {
		t.Fatalf("raised to %d", e.target.Load())
	}
	if e.Status().Target != 40 {
		t.Fatal("status shows the set number, not the target")
	}
}

func guests(hs *hashState) []int32 {
	var out []int32
	for g := 0; g < 8; g++ {
		out = append(out, hs.slot(g).guest.Load())
	}
	return out
}

func TestMayMove(t *testing.T) {
	e := testEngine(t, 16)
	now := time.Now()
	if !e.mayMove(now) {
		t.Fatal("first move refused")
	}
	e.movedAt.Store(now.UnixNano())
	if e.mayMove(now.Add(10 * time.Second)) {
		t.Fatal("two moves within relayMoveEvery")
	}
	later := now.Add(time.Hour)
	e.quotaAt.Store(later.UnixNano())
	if e.mayMove(later.Add(time.Minute)) {
		t.Fatal("moved right after a 486")
	}
	e.wokeAt.Store(later.Add(5 * time.Minute).UnixNano())
	if e.mayMove(later.Add(6 * time.Minute)) {
		t.Fatal("moved while dozing")
	}
	if !e.mayMove(later.Add(8 * time.Minute)) {
		t.Fatal("no move after all waits")
	}
}

func TestOfflineGate(t *testing.T) {
	var g offlineGate
	ctx := context.Background()
	if !g.wait(ctx) {
		t.Fatal("online wait failed")
	}
	now := time.Now()
	if !g.down(now, time.Hour) || g.down(now, time.Hour) {
		t.Fatal("down should report once a minute")
	}
	done := make(chan bool)
	go func() { done <- g.wait(ctx) }()
	select {
	case <-done:
		t.Fatal("wait returned while offline")
	case <-time.After(50 * time.Millisecond):
	}
	g.up()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("wait failed")
		}
	case <-time.After(time.Second):
		t.Fatal("up did not release the wait")
	}
	// The wait over: one route tries, the next waits again.
	g.down(time.Now(), 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	if !g.wait(ctx) {
		t.Fatal("the probing route was held")
	}
	c, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if g.wait(c) {
		t.Fatal("a second route went while the first was checking")
	}
}

func TestUnreachable(t *testing.T) {
	for _, m := range []string{
		"TURN: allocate: write udp4 1.2.3.4:5->6.7.8.9:3478: sendto: network is unreachable",
		`Post "https://calls.okcdn.ru/fb.do": dial tcp: lookup calls.okcdn.ru on [::1]:53: dial udp 1.2.3.4:53: connect: network is unreachable`,
		"wsasendto: A socket operation was attempted to an unreachable network.",
	} {
		if !unreachable(errors.New(m)) {
			t.Errorf("not unreachable: %s", m)
		}
	}
	if unreachable(errors.New("Allocate error response (error 486: Allocation Quota Reached)")) || unreachable(nil) {
		t.Error("false unreachable")
	}
}

func TestLogLimiter(t *testing.T) {
	var l logLimiter
	now := time.Now()
	n := 0
	for i := 0; i < 20; i++ {
		if _, ok := l.allow("route "+string(rune('0'+i%10))+" silent for 7s, replacing it", now); ok {
			n++
		}
	}
	if n != logRepeat {
		t.Fatalf("%d lines logged, want %d", n, logRepeat)
	}
	if _, ok := l.allow("connected", now); !ok {
		t.Fatal("another line was held")
	}
	line, ok := l.allow("route 3 silent for 9s, replacing it", now.Add(logWindow))
	if !ok || !strings.Contains(line, "and 17 more like it") {
		t.Fatalf("next window: %q %v", line, ok)
	}
}

// A relay is blamed only when routes through another answered well after
// it fell silent; when everything stops together (the WDTT server
// restarts, the network goes) none is.
func TestRelayDownProof(t *testing.T) {
	const a, b = "a:1", "b:1"
	var list []*session.Session
	for i := 0; i < 4; i++ {
		list = append(list, route(a), route(b))
	}
	stop := time.Now()
	set := func(sv string, at time.Time) {
		for _, s := range list {
			if s.Server == sv {
				s.LastRx.Store(at.UnixNano())
			}
		}
	}
	// Everything stopped at once; b's last pings came a moment later.
	set(a, stop.Add(-1500*time.Millisecond))
	set(b, stop.Add(-200*time.Millisecond))
	if n := answeredAfter(list, a, stop.Add(-1500*time.Millisecond).UnixNano()); n != 0 {
		t.Fatalf("blamed a relay for a common stop: %d", n)
	}
	// Only a stopped: b keeps answering.
	set(b, stop.Add(5*time.Second))
	if n := answeredAfter(list, a, stop.Add(-1500*time.Millisecond).UnixNano()); n != 4 {
		t.Fatalf("answered after = %d, want 4", n)
	}
}

// While the WDTT server answers no route, one route checks it, less often
// each time it fails; routes that failed together count once.
func TestSilentBackoff(t *testing.T) {
	var g offlineGate
	now := time.Now()
	for i := 0; i < 5; i++ {
		if d, _ := g.backoff(now, silentWait, silentWaitMax); d != silentWait {
			t.Fatalf("burst failure %d: wait %s", i, d)
		}
	}
	want := silentWait
	for i := 0; i < 5; i++ {
		g.mu.Lock()
		g.until = time.Now() // the wait is over: the next route checks
		g.mu.Unlock()
		if !g.wait(context.Background()) {
			t.Fatal("the checking route was held")
		}
		want = min(2*want, silentWaitMax)
		if d, _ := g.backoff(time.Now(), silentWait, silentWaitMax); d != want {
			t.Fatalf("check %d failed: wait %s, want %s", i, d, want)
		}
	}
	g.up()
	if d, _ := g.backoff(time.Now(), silentWait, silentWaitMax); d != silentWait {
		t.Fatalf("after up: wait %s", d)
	}
}

// Guests an earlier run left with unfreed allocations are skipped at the
// start; the two groups of a guest move together.
func TestStartGuestBusy(t *testing.T) {
	e := testEngine(t, 64) // guests 0..3, two groups each
	hs := e.hashes[0]
	before := time.Now().Add(-2 * time.Minute)
	hs.cache.Hold(hs.guestKey(0), before)
	hs.cache.Hold(hs.guestKey(4), before)
	hs.cache.Hold(hs.guestKey(1), time.Now().Add(-allocLife-time.Minute))
	got := []int32{}
	for g := 0; g < 4; g++ {
		got = append(got, hs.slot(g).guest.Load())
	}
	if want := []int32{5, 5, 1, 1}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("guests %v, want %v", got, want)
	}
	// This run's own holds do not make guests busy, and a clean stop
	// forgets them; an earlier run's stay.
	hs.cache.Hold(hs.guestKey(5), time.Now())
	if hs.busy(5, time.Now()) {
		t.Fatal("this run's guest judged busy")
	}
	hs.freeGuests()
	if !hs.cache.Held(hs.guestKey(5)).IsZero() || hs.cache.Held(hs.guestKey(0)).IsZero() {
		t.Fatal("freeGuests forgot the wrong holds")
	}
}

// More routes that meet error 486 at once: back down now, and wait twice
// as long before the next try.
func TestRaiseBackoff(t *testing.T) {
	e := testEngine(t, 64)
	now := time.Now()
	e.lowerTarget(now)
	e.quotaAt.Store(now.UnixNano())
	at := now.Add(targetRestore + time.Second)
	e.raiseTarget(at)
	if e.target.Load() != 64 {
		t.Fatalf("not raised: %d", e.target.Load())
	}
	e.quotaAt.Store(at.Add(2 * time.Second).UnixNano())
	e.lowerTarget(at.Add(2 * time.Second))
	if e.target.Load() != 56 || e.raiseFails.Load() != 1 {
		t.Fatalf("after a failed raise: target %d, fails %d", e.target.Load(), e.raiseFails.Load())
	}
	e.raiseTarget(at.Add(targetRestore + time.Minute))
	if e.target.Load() != 56 {
		t.Fatal("raised again after targetRestore")
	}
	at2 := at.Add(2*targetRestore + time.Minute)
	e.raiseTarget(at2)
	if e.target.Load() != 64 {
		t.Fatal("not raised after twice targetRestore")
	}
	// A 486 long after the raise: that number fitted.
	e.lowerTarget(at2.Add(time.Hour))
	if e.raiseFails.Load() != 0 {
		t.Fatalf("fails %d after a raise that held", e.raiseFails.Load())
	}
}
