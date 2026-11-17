//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Jetvac/turn-vk-client/core/winvpn"
)

// debugRun: "TurnVK.exe --debug-run" connects to the selected server,
// logs the adapter's packets and the packets Windows drops (pktmon) during
// the check after connecting, then disconnects and closes. Everything goes
// to the log; it takes under a minute.
var debugRun bool

// debugDir is where pktmon's files go.
func debugDir() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return os.TempDir()
	}
	return filepath.Join(dir, "TurnVK")
}

// pktmon runs Windows' packet monitor and returns its output.
func pktmon(args ...string) string {
	cmd := exec.Command("pktmon", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		s += " (" + err.Error() + ")"
	}
	return s
}

// startDrops starts recording the packets Windows drops.
func (a *app) startDrops() {
	_ = pktmon("stop")
	_ = pktmon("filter", "remove")
	etl := filepath.Join(debugDir(), "drops.etl")
	a.logf("debug: pktmon start: %s", firstLine(pktmon("start", "--capture", "--type", "drop", "--pkt-size", "96", "--file-name", etl)))
}

// stopDrops stops recording and logs the drops that concern the tunnel.
func (a *app) stopDrops(v *winvpn.VPN) {
	if v != nil {
		if c := winvpn.DebugCounts(v.Device()); c != "" {
			a.logf("debug: adapter: %s", c)
		}
	}
	a.logf("debug: pktmon stop: %s", firstLine(pktmon("stop")))
	etl := filepath.Join(debugDir(), "drops.etl")
	txt := filepath.Join(debugDir(), "drops.txt")
	a.logf("debug: pktmon etl2txt: %s", firstLine(pktmon("etl2txt", etl, "--out", txt)))
	b, err := os.ReadFile(txt)
	if err != nil {
		a.logf("debug: no drop log: %v", err)
		return
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n")
	a.logf("debug: pktmon recorded %d lines of drops (full list: %s)", len(lines), txt)
	// Drops of the tunnel's traffic first, then any others.
	shown := 0
	for _, pass := range []func(string) bool{
		func(l string) bool { return strings.Contains(l, "10.66.") || strings.Contains(l, "1.1.1.1") },
		func(l string) bool { return true },
	} {
		for i, l := range lines {
			if shown >= 40 {
				return
			}
			if strings.TrimSpace(l) == "" || !pass(l) {
				continue
			}
			// The drop reason is on the line; the packet follows it.
			next := ""
			if i+1 < len(lines) {
				next = " | " + strings.TrimSpace(lines[i+1])
			}
			a.logf("debug: drop: %s%s", strings.TrimSpace(l), next)
			lines[i] = ""
			shown++
		}
		if shown > 0 {
			return
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// finishDebugRun closes the app after the debug run.
func (a *app) finishDebugRun() {
	a.logf("debug run finished: closing")
	time.Sleep(time.Second)
	a.w.Dispatch(func() { a.w.Terminate() })
}
