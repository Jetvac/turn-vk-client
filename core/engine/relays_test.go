package engine

import (
	"testing"
	"time"

	"github.com/Jetvac/turn-vk-client/core/session"
)

// route returns a direct session through server (a test double: only the
// fields relays.go reads).
func route(server string) *session.Session {
	s := session.NewTestSession(server)
	return s
}

func TestRelayScoring(t *testing.T) {
	const good, worse = "95.163.34.154:19302", "90.156.234.247:19302"
	var list []*session.Session
	for i := 0; i < 8; i++ {
		list = append(list, route(good), route(worse))
	}
	var r relays
	now := time.Now()
	r.tick(list, now)
	// Three windows: the good relay loses 0.5 %, the worse one 8 %.
	for w := 1; w <= 3; w++ {
		for _, s := range list {
			if s.Server == good {
				s.RxPackets.Add(995)
				s.RxLost.Add(5)
			} else {
				s.RxPackets.Add(920)
				s.RxLost.Add(80)
			}
		}
		if !r.tick(list, now.Add(time.Duration(w)*relayWindow)) {
			t.Fatalf("window %d not closed", w)
		}
	}
	bad := r.bad()
	if _, ok := bad[worse]; !ok || len(bad) != 1 {
		t.Fatalf("bad = %v, want only %s", bad, worse)
	}
	if got := r.pick([]string{good, worse}, worse, list); got != good {
		t.Fatalf("pick = %s, want %s", got, good)
	}
	if got := r.pick([]string{good, worse}, good, list); got != good {
		t.Fatalf("pick = %s, want the default %s", got, good)
	}
	// Routes move off the worse relay one at a time, down to relayKeep.
	moved := 0
	for {
		s := r.moveOne(list)
		if s == nil {
			break
		}
		if s.Server != worse {
			t.Fatalf("moved a route on %s", s.Server)
		}
		for i, x := range list {
			if x == s {
				list[i] = route(good)
			}
		}
		moved++
	}
	if moved != 8-relayKeep {
		t.Fatalf("moved %d routes, want %d", moved, 8-relayKeep)
	}
}

// Equal relays, or too little traffic to judge: nothing changes.
func TestRelayScoringNeedsEvidence(t *testing.T) {
	const a, b = "a:1", "b:1"
	list := []*session.Session{route(a), route(b), route(a), route(b)}
	var r relays
	now := time.Now()
	r.tick(list, now)
	for w := 1; w <= 3; w++ {
		for _, s := range list {
			s.RxPackets.Add(40) // 160 packets a window: below relayMinPkts
			s.RxLost.Add(10)
		}
		r.tick(list, now.Add(time.Duration(w)*relayWindow))
	}
	if bad := r.bad(); len(bad) != 0 {
		t.Fatalf("judged on too few packets: %v", bad)
	}
	if r.pick([]string{a, b}, b, list) != b || r.moveOne(list) != nil {
		t.Fatal("changed routes without evidence")
	}
}

// A relay that failed a new route is avoided for a while, unless every
// relay failed.
func TestRelayDown(t *testing.T) {
	const a, b = "a:1", "b:1"
	var r relays
	now := time.Now()
	r.failed(a, now)
	if got := r.pick([]string{a, b}, a, nil); got != b {
		t.Fatalf("pick = %s, want %s", got, b)
	}
	r.failed(b, now)
	if got := r.pick([]string{a, b}, a, nil); got != a {
		t.Fatalf("all down: pick = %s, want the default %s", got, a)
	}
	r.down[a] = now.Add(-time.Second)
	r.down[b] = now.Add(-time.Second)
	if got := r.pick([]string{a, b}, a, nil); got != a {
		t.Fatalf("after relayDownFor: pick = %s", got)
	}
}
