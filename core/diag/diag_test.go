package diag

import (
	"strings"
	"testing"
	"time"

	"github.com/Jetvac/turn-vk-client/core/engine"
)

func TestRedact(t *testing.T) {
	for in, want := range map[string]string{
		"link wdtt://1.2.3.4:56000:51820:9000:pw:abc?pk=xyz tail": "link wdtt://<hidden> tail",
		"https://vk.com/call/join/AbCdEf_123-x":                   "https://vk.com/call/join/<hidden>",
		"GET ?access_token=vk1.a.secret&v=5":                      "GET ?access_token=<hidden>&v=5",
		"key MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=":        "key <hidden>",
		"VK call 4_ugJn2L…: joining as new guest 1":               "VK call 4_ugJn2L…: joining as new guest 1",
		"connected: address 10.66.67.6/32, MTU 1280":              "connected: address 10.66.67.6/32, MTU 1280",
	} {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestText(t *testing.T) {
	now := time.Now()
	r := &Report{
		App:      "TurnVK test 1.0",
		System:   []string{"os: test"},
		Settings: []string{"routes: 32"},
		Link:     "wdtt://1.2.3.4:56000:51820:9000:secretpw:hash1,hash2",
		Status: &engine.Status{State: "connected", Sessions: 2, Target: 32, Protocol: "direct", Since: now.Unix(),
			Paths: []engine.PathStatus{{ID: 0, Server: "5.6.7.8:3478", RTT: 40, Fresh: true, RxPackets: 99, Lost: 1}, {ID: 1, Server: "5.6.7.8:3478"}}},
		Diag:   &engine.Diag{Connected: now.Add(-time.Minute), Address: "10.0.0.2/32", MTU: 1280, Samples: []engine.Sample{{At: now, Rx: 2048, Tx: 100, Routes: 2}}},
		Checks: []Check{{Name: "x", OK: true, Result: "fine"}},
		Log:    []string{"12:00:00 started", "12:00:01 link wdtt://1.2.3.4:1:2:3:pw:h"},
	}
	s := r.Text()
	for _, want := range []string{"1.2.3.4, port 56000", "2 VK call(s)", "WireGuard handshake: NONE", "routes  2 (answering  1)", "loss 1.0%", "2.0 KB", "ok   x", "wdtt://<hidden>"} {
		if !strings.Contains(s, want) {
			t.Errorf("report lacks %q:\n%s", want, s)
		}
	}
	for _, bad := range []string{"secretpw", "hash1", ":pw:"} {
		if strings.Contains(s, bad) {
			t.Errorf("report leaks %q", bad)
		}
	}
}
