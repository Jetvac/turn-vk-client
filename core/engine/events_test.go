package engine

import (
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/Jetvac/turn-vk-client/core/session"
)

func events() []statsEvent {
	statsQ.mu.Lock()
	defer statsQ.mu.Unlock()
	return append([]statsEvent(nil), statsQ.events...)
}

// noise: words that do not compress, unlike real lines (and are not
// long enough for the redactor to hide).
func noise(n int) string {
	var b strings.Builder
	for b.Len() < n {
		w := make([]byte, 4)
		for i := range w {
			w[i] = byte(rand.Uint32())
		}
		b.WriteString(hex.EncodeToString(w) + " ")
	}
	return b.String()
}

// Lines of one kind in a minute are one entry with a count.
func TestEventsCollapse(t *testing.T) {
	resetStatsQ()
	now := time.Unix(1000, 0)
	addEvent("route 3 (1.2.3.4:3478) silent for 5s, replacing it", evNormal, now)
	addEvent("idle: 4 of 32 routes kept", evRoutine, now)
	addEvent("route 7 (5.6.7.8:3478) silent for 6s, replacing it", evNormal, now.Add(time.Second))
	addEvent("route 9 (5.6.7.8:3478) silent for 6s, replacing it (and 4 more like it)", evNormal, now.Add(2*time.Second))
	ev := events()
	if len(ev) != 2 {
		t.Fatalf("%d entries: %+v", len(ev), ev)
	}
	r := ev[0]
	if r.N != 7 || r.Last != now.Add(2*time.Second).UnixMilli() || !strings.HasPrefix(r.Msg, "route 3") || r.Msg2 != "route 9 (5.6.7.8:3478) silent for 6s, replacing it" {
		t.Fatalf("%+v", r)
	}
}

// A full minute makes room for important lines by dropping routine ones;
// the user's marks are never dropped for other lines.
func TestEventsPriority(t *testing.T) {
	resetStatsQ()
	now := time.Now()
	for i := 0; i < statsEventsMax; i++ {
		addEvent(fmt.Sprintf("idle: kind %c%c", 'a'+i%26, 'a'+i/26), evRoutine, now)
	}
	addEvent("no answer from the server for 1m0s; reconnecting", evNormal, now)
	addEvent("idle: one more", evRoutine, now)
	ev := events()
	if len(ev) != statsEventsMax || ev[len(ev)-1].level != evNormal || statsQ.dropped != 2 {
		t.Fatalf("%d events, last %+v, %d dropped", len(ev), ev[len(ev)-1], statsQ.dropped)
	}
	resetStatsQ()
	for i := 0; i < statsEventsMax; i++ {
		Mark(nil, fmt.Sprint(i))
	}
	addEvent("route 1 silent", evNormal, now)
	for _, e := range events() {
		if e.level != evMark {
			t.Fatalf("a mark dropped for %q", e.Msg)
		}
	}
}

// More events than one datagram holds go in further parts of the same
// minute; beyond statsParts the least important are left out and counted.
func TestStatsReportParts(t *testing.T) {
	resetStatsQ()
	e := &Engine{cfg: Config{Sessions: 32}}
	Mark(nil, "telegram does not load")
	for i := 0; i < statsEventsMax-1; i++ {
		level := evNormal
		if i%2 == 0 {
			level = evRoutine
		}
		addEvent(fmt.Sprintf("kind%c%c %s", 'a'+i%26, 'a'+i/26, noise(180)), level, time.Now())
	}
	e.queueStats(statsMinute{T: 42})
	if n := len(statsQ.reports); n < 2 || n > statsParts {
		t.Fatalf("%d parts", n)
	}
	var seq any
	kept, mark := 0, false
	for i, r := range statsQ.reports {
		if len(r.body) > session.MaxStats {
			t.Fatalf("part %d: %d bytes", i, len(r.body))
		}
		m := inflate(t, r.body)
		if i == 0 {
			seq = m["seq"]
			if m["m"] == nil || m["ev_dropped"] == nil {
				t.Fatalf("first part %v", m)
			}
		} else if m["seq"] != seq || m["part"] != float64(i) || m["m"] != nil {
			t.Fatalf("part %d: %v", i, m)
		}
		for _, x := range m["ev"].([]any) {
			kept++
			mark = mark || strings.Contains(x.(map[string]any)["m"].(string), "telegram")
		}
	}
	if !mark || kept >= statsEventsMax {
		t.Fatalf("%d kept, mark %v", kept, mark)
	}
}

// Reports the queue let go are named in the next one.
func TestStatsLost(t *testing.T) {
	resetStatsQ()
	e := &Engine{cfg: Config{Sessions: 4}}
	for i := 1; i <= statsQueueMax+3; i++ {
		e.queueStats(statsMinute{T: int64(i)})
	}
	// Each report names the minutes let go since the one before.
	n, from := 0.0, 0.0
	for _, r := range statsQ.reports {
		if l, ok := inflate(t, r.body)["lost"].(map[string]any); ok {
			n += l["n"].(float64)
			if from == 0 {
				from = l["from"].(float64)
			}
		}
	}
	if n != 2 || from != 1 {
		t.Fatalf("%v lost from %v", n, from)
	}
	if m := inflate(t, statsQ.reports[len(statsQ.reports)-1].body); m["seq"] != float64(statsQueueMax+3) {
		t.Fatalf("seq %v", m["seq"])
	}
}

// The first end of a connection counts, and is told once.
func TestDowntime(t *testing.T) {
	resetStatsQ()
	t0 := time.Unix(1000, 0)
	noteDown("failed: network unreachable", t0)
	noteDown("connecting was stopped", t0.Add(time.Minute))
	line, ok := takeDown(t0.Add(2*time.Hour + 18*time.Minute))
	if !ok || !strings.Contains(line, "2h18m0s") || !strings.Contains(line, "network unreachable") {
		t.Fatalf("%q", line)
	}
	if _, ok := takeDown(t0); ok {
		t.Fatal("told twice")
	}
}

func TestMarkNotConnected(t *testing.T) {
	resetStatsQ()
	line := Mark(nil, "  Telegram\n  lags  ")
	if !strings.Contains(line, "«Telegram lags»") || !strings.HasSuffix(line, "(not connected)") {
		t.Fatalf("%q", line)
	}
	if ev := events(); len(ev) != 1 || ev[0].level != evMark {
		t.Fatalf("%+v", ev)
	}
}
