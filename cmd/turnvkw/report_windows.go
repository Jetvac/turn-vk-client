//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Jetvac/turn-vk-client/core/diag"
	"github.com/Jetvac/turn-vk-client/core/engine"
	"github.com/Jetvac/turn-vk-client/core/link"
	"github.com/Jetvac/turn-vk-client/core/winvpn"
)

// reportResult goes to the page when a report is ready.
type reportResult struct {
	Text   string `json:"text"`
	Path   string `json:"path"`
	Copied bool   `json:"copied"`
	Error  string `json:"error"`
}

// report builds the diagnostic report (the checks take a few seconds),
// saves it next to the log, copies it and hands it to the page.
func (a *app) report() {
	a.mu.Lock()
	e, v := a.eng, a.vpn
	r := &diag.Report{
		App: "TurnVK Windows " + version,
		Settings: []string{
			fmt.Sprintf("routes: %d, disguise: %s, connect at start: %v", a.s.Sessions, a.s.Obfs, a.s.ConnectOnStart),
			fmt.Sprintf("saved servers: %d", len(a.s.Profiles)),
		},
		Error: a.lastErr,
		Log:   append([]string(nil), a.logs...),
	}
	if p := a.current(); p != nil {
		r.Link = p.Link
	}
	last := a.last
	if a.health != "" {
		r.Settings = append(r.Settings, "check after connecting: "+a.health)
	}
	a.mu.Unlock()

	r.System = append([]string{
		"device: " + a.devID,
		fmt.Sprintf("program: %s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH),
	}, winvpn.Describe(v)...)
	opts := diag.CheckOptions{}
	if l, err := link.Parse(r.Link); err == nil {
		opts.Server = l.Host
	}
	if e != nil {
		st, d := e.Status(), e.Diag()
		r.Status, r.Diag = &st, &d
		if st.State == engine.StateConnected {
			// Only TurnVK's own sockets bypass the adapter: the checks'
			// connections go through the tunnel.
			opts.Tunnel = true
			opts.DNS = d.DNS
			if len(opts.DNS) == 0 {
				opts.DNS = []string{"1.1.1.1"}
			}
		}
	}
	if e == nil && last != nil {
		// Not connected now: the report shows the connection that ended.
		r.Settings = append(r.Settings, "not connected now; connection below ended at "+last.Ended.Format("15:04:05"))
		r.Status, r.Diag = &last.Status, &last.Diag
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	r.Checks = diag.RunChecks(ctx, opts)
	cancel()

	res := reportResult{Text: r.Text()}
	if dir, err := os.UserCacheDir(); err == nil {
		res.Path = filepath.Join(dir, "TurnVK", "report-"+time.Now().Format("20060102-150405")+".txt")
		if err := os.WriteFile(res.Path, []byte(res.Text), 0o600); err != nil {
			res.Path = ""
		}
	}
	if err := setClipboard(res.Text); err != nil {
		res.Error = err.Error()
	} else {
		res.Copied = true
	}
	a.logf("diagnostic report ready%s", map[bool]string{true: ": " + res.Path, false: ""}[res.Path != ""])
	a.eval("onReport", res)
}

// showFile opens Explorer with the file selected.
func showFile(path string) {
	params, _ := windows.UTF16PtrFromString(`/select,"` + path + `"`)
	exe, _ := windows.UTF16PtrFromString("explorer.exe")
	_ = windows.ShellExecute(0, nil, exe, params, nil, windows.SW_SHOWNORMAL)
}

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	kernel32         = windows.NewLazySystemDLL("kernel32.dll")
	openClipboard    = user32.NewProc("OpenClipboard")
	closeClipboard   = user32.NewProc("CloseClipboard")
	emptyClipboard   = user32.NewProc("EmptyClipboard")
	setClipboardData = user32.NewProc("SetClipboardData")
	globalAlloc      = kernel32.NewProc("GlobalAlloc")
	globalLock       = kernel32.NewProc("GlobalLock")
	globalUnlock     = kernel32.NewProc("GlobalUnlock")
	globalFree       = kernel32.NewProc("GlobalFree")
	moveMemory       = kernel32.NewProc("RtlMoveMemory")
)

// setClipboard puts text on the Windows clipboard.
func setClipboard(text string) error {
	const cfUnicodeText, gmemMoveable = 13, 0x0002
	u, err := windows.UTF16FromString(text)
	if err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	opened := false
	for range 10 { // another program may hold it for a moment
		if r, _, _ := openClipboard.Call(0); r != 0 {
			opened = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !opened {
		return errors.New("the clipboard is busy")
	}
	defer closeClipboard.Call()
	emptyClipboard.Call()
	size := uintptr(len(u) * 2)
	h, _, err := globalAlloc.Call(gmemMoveable, size)
	if h == 0 {
		return fmt.Errorf("GlobalAlloc: %w", err)
	}
	p, _, err := globalLock.Call(h)
	if p == 0 {
		globalFree.Call(h)
		return fmt.Errorf("GlobalLock: %w", err)
	}
	moveMemory.Call(p, uintptr(unsafe.Pointer(&u[0])), size)
	globalUnlock.Call(h)
	if r, _, err := setClipboardData.Call(cfUnicodeText, h); r == 0 {
		globalFree.Call(h)
		return fmt.Errorf("SetClipboardData: %w", err)
	}
	return nil
}
