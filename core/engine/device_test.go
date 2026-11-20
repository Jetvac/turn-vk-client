package engine

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The app's CPU time grows with work; the statistics count it per minute.
func TestProcessCPU(t *testing.T) {
	a := processCPU()
	x := 0
	for end := time.Now().Add(50 * time.Millisecond); time.Now().Before(end); x++ {
	}
	if b := processCPU(); b <= a || x == 0 {
		t.Fatalf("CPU time %v then %v", a, b)
	}
}

// A minute carries the wakes, CPU and device state under short names.
func TestStatsMinuteDevice(t *testing.T) {
	m := statsMinute{Wakes: 3, CPU: 120, Dev: &DeviceState{Batt: 57, Screen: false, Doze: true, MAh: 2410, MA: -85}}
	b, _ := json.Marshal(m)
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	dev, _ := got["dev"].(map[string]any)
	if got["wakes"] != 3.0 || got["cpu_ms"] != 120.0 || dev["batt"] != 57.0 || dev["screen"] != false || dev["doze"] != true || dev["mah"] != 2410.0 {
		t.Fatalf("%s", b)
	}
	b, _ = json.Marshal(statsMinute{})
	got = nil
	if json.Unmarshal(b, &got); got["dev"] != nil || got["wakes"] != nil {
		t.Fatalf("empty fields sent: %s", b)
	}
}

// A long event is cut between characters, never inside one.
func TestNoteEventCut(t *testing.T) {
	msg := strings.Repeat("я", statsEventLen) // 2 bytes each
	noteEvent("x" + msg)
	statsQ.mu.Lock()
	got := statsQ.events[len(statsQ.events)-1].Msg
	statsQ.mu.Unlock()
	if !utf8.ValidString(got) || !strings.HasSuffix(got, "…") {
		t.Fatalf("cut inside a character: %q", got[len(got)-8:])
	}
}
