//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Jetvac/turn-vk-client/core/diag"
	"github.com/Jetvac/turn-vk-client/core/engine"
	"github.com/Jetvac/turn-vk-client/core/update"
)

// release is a newer version for the page.
type release = update.Release

// isWindowsAsset picks the window app from a release's files.
func isWindowsAsset(name string) bool {
	return strings.HasPrefix(name, "TurnVK-") && strings.HasSuffix(name, "-windows-amd64.exe")
}

// checkUpdates looks for a newer release now and then every few hours.
func (a *app) checkUpdates(stop <-chan struct{}) {
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		a.checkUpdate(false)
		t.Reset(6 * time.Hour)
	}
}

// checkUpdate asks GitHub; manual: the user pressed the button, so the
// page hears about "no update" and errors too.
func (a *app) checkUpdate(manual bool) {
	r, err := update.Latest(context.Background(), version, isWindowsAsset)
	if err != nil {
		if manual {
			a.eval("onUpdateState", map[string]any{"error": "не удалось проверить обновления: " + err.Error()})
		}
		return
	}
	a.mu.Lock()
	changed := (r == nil) != (a.update == nil) || (r != nil && a.update != nil && r.Version != a.update.Version)
	a.update = r
	a.mu.Unlock()
	if changed && r != nil {
		a.logf("update available: %s", r.Version)
		// The window may stay hidden for days (the icon by the clock).
		if theTray != nil && !manual {
			theTray.balloon("Доступна TurnVK "+r.Version, "Откройте TurnVK и нажмите «Обновить»: настройки и серверы сохранятся.")
		}
	}
	if manual && r == nil {
		a.eval("onUpdateState", map[string]any{"latest": true})
	}
	a.push()
}

// installUpdate downloads the new version next to this program, swaps the
// files and starts it; this copy then closes. Windows lets a running
// program be renamed, not overwritten.
func (a *app) installUpdate() {
	a.mu.Lock()
	r := a.update
	a.mu.Unlock()
	fail := func(err error) {
		a.logf("update: %v", err)
		a.eval("onUpdateState", map[string]any{"error": "обновление не удалось: " + err.Error()})
	}
	if r == nil {
		fail(errors.New("нет новой версии"))
		return
	}
	exe, err := os.Executable()
	if err != nil {
		fail(err)
		return
	}
	a.logf("update: downloading %s", r.Asset)
	last := time.Time{}
	err = update.Download(context.Background(), r, exe+".new", func(done, total int64) {
		if time.Since(last) > 200*time.Millisecond {
			last = time.Now()
			a.eval("onUpdateState", map[string]any{"done": done, "total": total})
		}
	})
	if err != nil {
		fail(err)
		return
	}
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		os.Remove(exe + ".new")
		fail(fmt.Errorf("не удалось заменить программу: %w", err))
		return
	}
	if err := os.Rename(exe+".new", exe); err != nil {
		_ = os.Rename(old, exe)
		fail(fmt.Errorf("не удалось заменить программу: %w", err))
		return
	}
	a.logf("update: %s installed, restarting", r.Version)
	a.eval("onUpdateState", map[string]any{"restarting": true})
	// The connection goes down first: the new copy needs the adapter.
	<-a.disconnect()
	// Started from an elevated process, it is elevated without a prompt.
	cmd := exec.Command(exe, "--after-update")
	if err := cmd.Start(); err != nil {
		fail(fmt.Errorf("запустите TurnVK снова: %w", err))
		return
	}
	a.w.Dispatch(func() { a.w.Terminate() })
}

// cleanupUpdate removes what an update left behind.
func cleanupUpdate() {
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(exe + ".old")
		_ = os.Remove(exe + ".new.part")
	}
}

// selfCheck checks, a little after connecting, that the internet works
// through the tunnel, and says so in the log and the window.
func (a *app) selfCheck(e *engine.Engine, server string) {
	select {
	case <-e.Done():
		return
	case <-time.After(15 * time.Second):
	}
	if e.State() != engine.StateConnected {
		return
	}
	d := e.Diag()
	dns := d.DNS
	if len(dns) == 0 {
		dns = []string{"1.1.1.1"}
	}
	a.mu.Lock()
	v := a.vpn
	a.mu.Unlock()
	if debugRun {
		if v != nil {
			for _, l := range v.AdapterState() {
				a.logf("debug: adapter state: %s", l)
			}
		}
		a.startDrops()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	checks := diag.RunChecks(ctx, diag.CheckOptions{Tunnel: true, DNS: dns, Server: server})
	cancel()
	if debugRun {
		a.stopDrops(v)
		defer a.finishDebugRun()
	}
	var failed []string
	for _, c := range checks {
		mark := "ok"
		if !c.OK {
			mark = "FAIL"
			failed = append(failed, c.Name)
		}
		a.logf("check after connecting: %s %s (%s): %s", mark, c.Name, c.Took.Round(time.Millisecond), diag.Redact(c.Result))
	}
	health := ""
	byName := map[string]bool{}
	for _, c := range checks {
		byName[c.Name] = c.OK
	}
	dnsOK := true
	for _, d := range dns {
		dnsOK = dnsOK && byName["DNS of the tunnel ("+d+"): google.com"]
	}
	web := byName["HTTP connectivity (gstatic 204)"] || byName["exit address (cloudflare trace)"]
	switch {
	case !web && !dnsOK:
		health = "сайты и DNS через туннель не отвечают"
	case !web:
		health = "сайты через туннель не открываются (DNS работает)"
	case !dnsOK:
		health = "DNS через туннель не отвечает, поэтому сайты по именам не открываются"
	}
	if d2 := e.Diag(); health != "" {
		a.logf("check after connecting: the internet does not work through the tunnel (handshake %v, in %d B, out %d B)", d2.FirstHandshake > 0, d2.WGRx, d2.WGTx)
	} else if len(failed) == 0 {
		a.logf("check after connecting: the internet works through the tunnel")
	}
	a.mu.Lock()
	if a.eng == e {
		a.health = health
	}
	a.mu.Unlock()
	a.push()
}
