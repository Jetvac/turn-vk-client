//go:build windows

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	webview2 "github.com/jchv/go-webview2"

	"github.com/Jetvac/turn-vk-client/core/engine"
	"github.com/Jetvac/turn-vk-client/core/link"
	"github.com/Jetvac/turn-vk-client/core/netx"
	"github.com/Jetvac/turn-vk-client/core/vkcreds"
	"github.com/Jetvac/turn-vk-client/core/webcaptcha"
	"github.com/Jetvac/turn-vk-client/core/winvpn"
	"github.com/Jetvac/turn-vk-client/core/wrap"
)

// profile is a saved server: a wdtt:// link under a name the user chose.
type profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Link string `json:"link"`
}

// settings are the same as the Android app's, minus what Windows has no
// counterpart for (per-app bypass, the quick settings tile).
type settings struct {
	Profiles       []profile `json:"profiles"`
	Current        string    `json:"current"`
	Sessions       int       `json:"sessions"`
	Obfs           string    `json:"obfs"`
	ConnectOnStart bool      `json:"connect_on_start"`
}

// view is what the page shows; it gets a new copy on every change.
type view struct {
	Settings settings       `json:"settings"`
	Running  bool           `json:"running"`
	Status   *engine.Status `json:"status"`
	Error    string         `json:"error"`
	Device   string         `json:"device"`
	Version  string         `json:"version"`
	// OtherVPN names another VPN adapter that takes the internet traffic.
	OtherVPN string `json:"other_vpn"`
	// Health: the check after connecting found that the internet does
	// not work through the tunnel ("" when it does or before the check).
	Health string `json:"health"`
	// Update: a newer release on GitHub ("" when this one is the latest).
	Update *release `json:"update"`
}

type app struct {
	w       webview2.WebView
	path    string // settings file
	vkCache string
	devID   string
	captcha vkcreds.CaptchaSolver

	mu      sync.Mutex
	s       settings
	eng     *engine.Engine
	vpn     *winvpn.VPN
	cancel  context.CancelFunc
	lastErr string
	logs    []string
	logFile *os.File
	crash   *os.File
	stopped chan struct{} // closed when the last connection has been taken down
	health  string
	// last is the previous connection's state, for a report made after
	// disconnecting.
	last   *lastConn
	update *release
}

// lastConn is what a report shows of a connection that has ended.
type lastConn struct {
	eng    *engine.Engine
	Ended  time.Time
	Status engine.Status
	Diag   engine.Diag
}

const maxLogs = 1000

func newApp() *app {
	a := &app{stopped: make(chan struct{})}
	close(a.stopped)
	if dir, err := os.UserConfigDir(); err == nil {
		a.path = filepath.Join(dir, "TurnVK", "settings.json")
	}
	if dir, err := os.UserCacheDir(); err == nil {
		// The same file as the console client: a captcha solved in one
		// is not asked again in the other.
		a.vkCache = filepath.Join(dir, "turnvk", "vk-guests.json")
		// The log also goes to a file, for when the window is closed or
		// something has to be sent for a look.
		lp := filepath.Join(dir, "TurnVK", "turnvk.log")
		_ = os.MkdirAll(filepath.Dir(lp), 0o700)
		flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
		if fi, err := os.Stat(lp); err == nil && fi.Size() > 4<<20 {
			flags |= os.O_TRUNC
		}
		a.logFile, _ = os.OpenFile(lp, flags, 0o600)
		a.crash, _ = os.Create(filepath.Join(dir, "TurnVK", "crash.log"))
	}
	// The same device ID as the console client, so the server counts this
	// computer once.
	h, _ := os.Hostname()
	sum := sha256.Sum256([]byte("turnvk|" + h))
	a.devID = "pc-" + hex.EncodeToString(sum[:8])
	a.captcha = webcaptcha.New(a.logf)
	a.load()
	return a
}

func (a *app) load() {
	a.s = settings{Sessions: 32, Obfs: "audio"}
	if a.path == "" {
		return
	}
	b, err := os.ReadFile(a.path)
	if err != nil {
		return
	}
	if err := json.Unmarshal(b, &a.s); err != nil {
		a.logf("settings: %v", err)
	}
	if a.s.Sessions < 1 || a.s.Sessions > 64 {
		a.s.Sessions = 32
	}
	if a.s.Obfs != "video" {
		a.s.Obfs = "audio"
	}
}

// save writes the settings; a.mu is held.
func (a *app) save() {
	if a.path == "" {
		return
	}
	b, _ := json.MarshalIndent(a.s, "", "  ")
	_ = os.MkdirAll(filepath.Dir(a.path), 0o700)
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		_ = os.Rename(tmp, a.path)
	}
}

func (a *app) current() *profile {
	for i := range a.s.Profiles {
		if a.s.Profiles[i].ID == a.s.Current {
			return &a.s.Profiles[i]
		}
	}
	if len(a.s.Profiles) > 0 {
		return &a.s.Profiles[0]
	}
	return nil
}

func (a *app) logf(f string, args ...any) {
	line := time.Now().Format("15:04:05 ") + fmt.Sprintf(f, args...)
	a.mu.Lock()
	a.logs = append(a.logs, line)
	if len(a.logs) > maxLogs {
		a.logs = append([]string(nil), a.logs[len(a.logs)-maxLogs/2:]...)
	}
	if a.logFile != nil {
		a.logFile.WriteString(time.Now().Format("2006-01-02 ") + line + "\n")
	}
	a.mu.Unlock()
	a.eval("onLog", line)
}

// eval calls a function of the page with JSON arguments, from any goroutine.
func (a *app) eval(fn string, args ...any) {
	if a.w == nil {
		return
	}
	parts := make([]string, len(args))
	for i, v := range args {
		b, _ := json.Marshal(v)
		parts[i] = string(b)
	}
	js := "window." + fn + "&&window." + fn + "(" + strings.Join(parts, ",") + ")"
	a.w.Dispatch(func() { a.w.Eval(js) })
}

// snapshot builds the page's view; a.mu is held.
func (a *app) snapshot() view {
	v := view{Settings: a.s, Running: a.eng != nil, Error: a.lastErr, Device: a.devID, Version: version, OtherVPN: winvpn.OtherVPN(), Health: a.health, Update: a.update}
	v.Settings.Profiles = append([]profile(nil), a.s.Profiles...)
	if p := a.current(); p != nil {
		v.Settings.Current = p.ID
	}
	if a.eng != nil {
		st := a.eng.Status()
		v.Status = &st
	}
	return v
}

func (a *app) push() {
	a.mu.Lock()
	v := a.snapshot()
	a.mu.Unlock()
	a.eval("onView", v)
}

// bind exposes the page's calls. They run on the window's thread, so
// anything slow goes to a goroutine.
func (a *app) bind(w webview2.WebView) {
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	must(w.Bind("tvkView", func() view {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.snapshot()
	}))
	must(w.Bind("tvkLogs", func() []string {
		a.mu.Lock()
		defer a.mu.Unlock()
		return append([]string(nil), a.logs...)
	}))
	must(w.Bind("tvkClearLogs", func() {
		a.mu.Lock()
		a.logs = nil
		a.mu.Unlock()
	}))
	must(w.Bind("tvkSaveProfile", func(p profile) (string, error) {
		p.Link = strings.TrimSpace(p.Link)
		p.Name = strings.TrimSpace(p.Name)
		l, err := link.Parse(p.Link)
		if err != nil {
			return "", fmt.Errorf("ссылка не подходит: %v", err)
		}
		if p.Name == "" {
			p.Name = autoName(l.Host)
		}
		a.mu.Lock()
		if p.ID == "" {
			p.ID = newID()
		}
		found := false
		for i := range a.s.Profiles {
			old := a.s.Profiles[i]
			if old.ID != p.ID {
				continue
			}
			// A name the app made up follows the link to a new server.
			if ol, err := link.Parse(old.Link); err == nil && p.Name == old.Name && old.Name == autoName(ol.Host) {
				p.Name = autoName(l.Host)
			}
			a.s.Profiles[i], found = p, true
		}
		if !found {
			a.s.Profiles = append(a.s.Profiles, p)
		}
		a.s.Current = p.ID
		a.save()
		a.mu.Unlock()
		a.push()
		return p.ID, nil
	}))
	must(w.Bind("tvkDeleteProfile", func(id string) {
		a.mu.Lock()
		out := a.s.Profiles[:0]
		for _, p := range a.s.Profiles {
			if p.ID != id {
				out = append(out, p)
			}
		}
		a.s.Profiles = out
		if a.s.Current == id {
			a.s.Current = ""
		}
		a.save()
		a.mu.Unlock()
		a.push()
	}))
	must(w.Bind("tvkSelect", func(id string) {
		a.mu.Lock()
		a.s.Current = id
		a.save()
		a.mu.Unlock()
		a.push()
	}))
	must(w.Bind("tvkSetOptions", func(sessions int, obfs string, connectOnStart bool) {
		a.mu.Lock()
		if sessions >= 1 && sessions <= 64 {
			a.s.Sessions = sessions
		}
		if obfs == "audio" || obfs == "video" {
			a.s.Obfs = obfs
		}
		a.s.ConnectOnStart = connectOnStart
		a.save()
		a.mu.Unlock()
		a.push()
	}))
	must(w.Bind("tvkReport", func() { go a.report() }))
	must(w.Bind("tvkCheckUpdate", func() { go a.checkUpdate(true) }))
	must(w.Bind("tvkInstallUpdate", func() { go a.installUpdate() }))
	must(w.Bind("tvkShowFile", func(path string) {
		// Only the reports this app saved.
		if dir, err := os.UserCacheDir(); err == nil && filepath.Dir(path) == filepath.Join(dir, "TurnVK") {
			go showFile(path)
		}
	}))
	must(w.Bind("tvkConnect", func() error { return a.connect() }))
	must(w.Bind("tvkDisconnect", func() { a.disconnect() }))
}

// addLink selects the saved server with this link, or saves it as a new one.
func (a *app) addLink(raw string) error {
	raw = strings.TrimSpace(raw)
	l, err := link.Parse(raw)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.s.Profiles {
		if p.Link == raw {
			a.s.Current = p.ID
			a.save()
			return nil
		}
	}
	p := profile{ID: newID(), Name: autoName(l.Host), Link: raw}
	a.s.Profiles = append(a.s.Profiles, p)
	a.s.Current = p.ID
	a.save()
	return nil
}

// autoName names a server the user did not name.
func autoName(host string) string { return "Сервер " + host }

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// connect starts a connection to the selected server; it returns at once
// and the page follows the status.
func (a *app) connect() error {
	// logf takes a.mu: the line is written after the unlock below.
	var note string
	defer func() {
		if note != "" {
			a.logf("%s", note)
		}
	}()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.eng != nil {
		return nil
	}
	p := a.current()
	if p == nil {
		return errors.New("добавьте ссылку wdtt://")
	}
	l, err := link.Parse(p.Link)
	if err != nil {
		return err
	}
	// The previous connection must be gone: the adapter is the same.
	select {
	case <-a.stopped:
	default:
		return errors.New("предыдущее подключение ещё закрывается, попробуйте через пару секунд")
	}
	var e *engine.Engine
	v, err := winvpn.New(a.logf, func() {
		a.mu.Lock()
		cur := a.eng
		a.mu.Unlock()
		if cur != nil && cur == e {
			cur.Reconnect("the network changed")
		}
	})
	if err != nil {
		return err
	}
	e, err = engine.New(engine.Config{
		Link: l, DeviceID: a.devID, Sessions: a.s.Sessions, Mode: wrap.ParseMode(a.s.Obfs),
		Net:     &netx.Net{DNS: netx.DefaultDNS, Protect: v.Protect},
		Captcha: a.captcha,
		VKCache: a.vkCache,
		Logf:    a.logf,
		// Not inline: the engine may report while a.mu is held here, and
		// push asks the engine for its status.
		OnStatus: func(engine.Status) { go a.push() },
	})
	if err != nil {
		v.Close()
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.eng, a.vpn, a.cancel, a.lastErr = e, v, cancel, ""
	a.stopped = make(chan struct{})
	stopped := a.stopped
	note = fmt.Sprintf("connecting to %s (%s), %d routes", p.Name, l.Host, a.s.Sessions)
	a.health = ""
	go func() {
		err := e.Start(ctx, v.Open)
		if err == nil {
			go a.selfCheck(e, l.Host)
			<-e.Done()
			err = e.Err()
		}
		a.mu.Lock()
		a.remember(e)
		mine := a.eng == e
		if mine {
			a.eng, a.vpn, a.cancel = nil, nil, nil
			if err != nil {
				a.lastErr = err.Error()
			}
		}
		a.mu.Unlock()
		if mine {
			if err != nil {
				a.logf("stopped: %v", err)
			}
			cancel()
			e.Stop()
			v.Close()
			close(stopped)
		}
		a.push()
	}()
	go a.push()
	return nil
}

// disconnect takes the connection down; done is closed once the adapter is
// gone and the TURN allocations are released.
func (a *app) disconnect() (done <-chan struct{}) {
	a.mu.Lock()
	e, v, cancel, stopped := a.eng, a.vpn, a.cancel, a.stopped
	a.remember(e)
	a.eng, a.vpn, a.cancel, a.lastErr, a.health = nil, nil, nil, "", ""
	a.mu.Unlock()
	if e == nil {
		return stopped
	}
	a.logf("disconnecting")
	go func() {
		cancel()
		e.Stop()
		v.Close()
		close(stopped)
		a.push()
	}()
	go a.push()
	return stopped
}

// tick refreshes the speed once a second while connected.
func (a *app) tick(stop <-chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			a.mu.Lock()
			on := a.eng != nil
			a.mu.Unlock()
			if on {
				a.push()
			}
		}
	}
}

// remember keeps a connection's state for later reports; a.mu is held.
func (a *app) remember(e *engine.Engine) {
	if e == nil || (a.last != nil && a.last.eng == e) {
		return
	}
	st, d := e.Status(), e.Diag()
	if d.Connected.IsZero() {
		return
	}
	a.last = &lastConn{eng: e, Ended: time.Now(), Status: st, Diag: d}
}
