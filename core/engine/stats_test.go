package engine

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/Jetvac/turn-vk-client/core/session"
)

func resetStatsQ() {
	statsQ.mu.Lock()
	statsQ.reports, statsQ.events, statsQ.dropped = nil, nil, 0
	statsQ.mu.Unlock()
}

func inflate(t *testing.T, b []byte) map[string]any {
	t.Helper()
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(zr)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestStatsReport(t *testing.T) {
	resetStatsQ()
	e := &Engine{cfg: Config{Sessions: 16, Client: "TurnVK test"}}
	noteEvent("connecting to wdtt://secret-link-should-not-leave")
	noteEvent("WireGuard: the server answered the handshake")
	e.queueStats(statsMinute{T: 1, Rx: 100, Routes: 16})
	if len(statsQ.reports) != 1 || len(statsQ.events) != 0 {
		t.Fatalf("%d reports, %d events left", len(statsQ.reports), len(statsQ.events))
	}
	r := statsQ.reports[0]
	if len(r.body) > session.MaxStats || r.id == 0 {
		t.Fatalf("report %d bytes, id %d", len(r.body), r.id)
	}
	m := inflate(t, r.body)
	if m["client"] != "TurnVK test" || len(m["ev"].([]any)) != 2 || len(m["m"].([]any)) != 1 {
		t.Fatalf("report %v", m)
	}
	if b, _ := json.Marshal(m); strings.Contains(string(b), "secret-link") {
		t.Fatalf("a link left the device: %s", b)
	}
	e.statsAck(r.id)
	if len(statsQ.reports) != 0 || !e.statsAcked.Load() {
		t.Fatal("acknowledged report still queued")
	}
}

// Many long, varied lines do not fit one datagram: the oldest go, the
// report says how many.
func TestStatsReportFits(t *testing.T) {
	resetStatsQ()
	e := &Engine{cfg: Config{Sessions: 32}}
	for i := 0; i < statsEventsMax+10; i++ {
		noteEvent(strings.Repeat(string(rune('a'+i%26)), 10) + " route " + strings.Repeat("x", i) + " " + string(rune('A'+i%26)) + strings.Repeat("q", 150))
	}
	e.queueStats(statsMinute{T: 1})
	if len(statsQ.reports) != 1 {
		t.Fatal("no report")
	}
	r := statsQ.reports[0]
	if len(r.body) > session.MaxStats {
		t.Fatalf("%d bytes", len(r.body))
	}
	m := inflate(t, r.body)
	if m["ev_dropped"] == nil {
		t.Fatalf("nothing dropped: %d events", len(m["ev"].([]any)))
	}
}

func TestStatsQueueBounded(t *testing.T) {
	resetStatsQ()
	e := &Engine{cfg: Config{Sessions: 4}}
	for i := 0; i < statsQueueMax+5; i++ {
		e.queueStats(statsMinute{T: int64(i)})
	}
	if len(statsQ.reports) != statsQueueMax {
		t.Fatalf("%d queued", len(statsQ.reports))
	}
}
