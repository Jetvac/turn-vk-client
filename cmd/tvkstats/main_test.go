package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 20, 16, 0, 0, 0, time.UTC)

// fake writes an hour of two devices' reports: from minute 10 to 20 only
// "a" loses packets, from 30 to 40 both do, and at 50 "a"'s tunnel stalls
// while its routes answer; "a" marks the moment at 52.
func fake(t *testing.T) string {
	var b bytes.Buffer
	rec := func(dev string, rep map[string]any, at time.Time) {
		r, _ := json.Marshal(rep)
		line, _ := json.Marshal(map[string]any{"type": "client", "dev": dev, "t": at.UnixMilli(), "r": json.RawMessage(r)})
		b.Write(append(line, '\n'))
	}
	for i := 0; i < 60; i++ {
		at := t0.Add(time.Duration(i) * time.Minute)
		for _, dev := range []string{"aaaa1111", "bbbb2222"} {
			lost := 0
			if (dev == "aaaa1111" && i >= 10 && i < 20) || (i >= 30 && i < 40) {
				lost = 100
			}
			m := map[string]any{"t": at.UnixMilli(), "state": "connected", "routes": 32, "fresh": 32, "target": 32,
				"rtt": 20, "lost": lost, "rx_pk": 1000, "net": map[string]any{"kind": "wifi", "rssi": -60}}
			rep := map[string]any{"client": "TurnVK 0.9.2 android", "seq": i + 1, "m": []any{m}}
			if dev == "aaaa1111" && i == 50 {
				rep["ev"] = []any{map[string]any{"t": at.UnixMilli(), "m": "no answer from the server for 1m0s while sending; every path answers, re-keying"}}
			}
			if dev == "aaaa1111" && i == 52 {
				rep["ev"] = []any{map[string]any{"t": at.UnixMilli(), "m": "user mark: something is wrong now: «telegram»"}}
			}
			rec(dev, rep, at)
		}
	}
	p := filepath.Join(t.TempDir(), "2026-11-20-16.jsonl")
	if err := os.WriteFile(p, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestShow(t *testing.T) {
	a, err := load(fake(t))
	if err != nil {
		t.Fatal(err)
	}
	d, err := a.find("aaaa")
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	show(&out, a, d, t0, t0.Add(time.Hour), 10*time.Minute, time.UTC, false)
	got := out.String()
	for _, want := range []string{
		"11-20 16:10 – 16:20  this device's network or ISP: only this device was affected",
		"11-20 16:30 – 16:40  everyone at once: the server or VK, not this device",
		"11-20 16:50 – 17:00  TurnVK on this device: the tunnel stalled while its routes answered",
		"The user's mark at 16:52:00: something is wrong now: «telegram»",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	var ov strings.Builder
	overview(&ov, a, time.UTC)
	if !strings.Contains(ov.String(), "bbbb2222") {
		t.Fatalf("overview:\n%s", ov.String())
	}
}

func TestParseTime(t *testing.T) {
	ref := time.Date(2026, 11, 21, 13, 0, 0, 0, time.UTC)
	for s, want := range map[string]string{
		"2026-11-20 07:30": "2026-11-20 07:30",
		"11-20 07:30":      "2026-11-20 07:30",
		"07:30":            "2026-11-21 07:30",
	} {
		got, err := parseTime(s, ref, time.UTC)
		if err != nil || got.Format("2006-01-02 15:04") != want {
			t.Errorf("%q: %v %v", s, got, err)
		}
	}
	if !newer("TurnVK 0.9.1 windows", "TurnVK 0.8.10 android") || newer("TurnVK 0.8.7 android", "TurnVK 0.8.7 windows") {
		t.Fatal("versions")
	}
}
