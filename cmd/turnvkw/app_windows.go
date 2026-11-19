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
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	webview2 "github.com/jchv/go-webview2"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/Jetvac/turn-vk-client/core/engine"
	"github.com/Jetvac/turn-vk-client/core/link"
	"github.com/Jetvac/turn-vk-client/core/netx"
	"github.com/Jetvac/turn-vk-client/core/split"
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
// counterpart for (the quick settings tile), plus split tunneling by
// program.
type settings struct {
	Profiles       []profile `json:"profiles"`
	Current        string    `json:"current"`
	Sessions       int       `json:"sessions"`
	Obfs           string    `json:"obfs"`
	ConnectOnStart bool      `json:"connect_on_start"`
	// Autostart mirrors the Task Scheduler task (autostart_windows.go).
	Autostart bool `json:"autostart"`
	// NoStats: send the server no statistics (on by default).
	NoStats bool `json:"no_stats"`
	// CloseQuits: closing the window quits TurnVK instead of leaving it
	// in the notification area (tray_windows.go).
	CloseQuits bool `json:"close_quits"`
	// TrayTold: the notification "TurnVK works in the background" was shown.
	TrayTold bool `json:"tray_told"`
	// Split: which programs go through the VPN (split tunneling).
	Split split.Rules `json:"split"`
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
	// Lists: the country and site lists of split tunneling.
	Lists listsView `json:"lists"`
	// Mode: the split tunneling mode the rules are in (split.ModeOf).
	Mode string `json:"mode"`
	// Net: the network now ("Wi-Fi «Home»", "кабель"; "" when unknown or
	// not connected); NetRule: the network rule in use ("" for none) and
	// EffMode: the mode applied because of it.
	Net        string `json:"net"`
	NetKey     string `json:"net_key"`
	NetRule    string `json:"net_rule"`
	NetRuleKey string `json:"net_rule_key"`
	EffMode    string `json:"eff_mode"`
	// Notes on the rules (split.CheckRules).
	Notes []split.RuleNote `json:"notes"`
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
	router  *split.Router // between the adapter and WireGuard, while connected
	fake    *split.Fake   // placeholder addresses of sites sent direct, kept across connections
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
	lists  listsState
	// The physical network while connected (split rules by network).
	netKind, netName string
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
	a.fake = split.NewFake()
	a.load()
	a.loadLists() // before the window: nothing to show yet
	return a
}

func (a *app) load() {
	a.s = settings{Sessions: 32, Obfs: "audio", Split: split.DefaultRules()}
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
	a.s.Split.Normalize()
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
	v.Lists = a.listsView()
	v.Mode = split.ModeOf(a.s.Split)
	v.Notes = split.CheckRules(a.s.Split)
	if a.eng != nil && a.netKind != "" {
		v.NetKey = split.NetworkKey(a.netKind, a.netName)
		v.Net = split.NetworkName(v.NetKey)
	}
	if eff, key := a.effective(); key != "" {
		v.NetRule, v.NetRuleKey, v.EffMode = split.NetworkName(key), key, split.ModeOf(eff)
	}
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
	theTray.setTip(trayTip(v))
	// VK's check needs the window: bring it up from the background.
	if v.Status != nil && v.Status.State == engine.StateCaptcha {
		theTray.showOnce("captcha")
	} else {
		theTray.showOnce("")
	}
}

// trayTip is the text under the mouse on the tray icon.
func trayTip(v view) string {
	if !v.Running || v.Status == nil {
		return "TurnVK — отключено"
	}
	switch v.Status.State {
	case engine.StateConnected:
		return "TurnVK — подключено"
	case engine.StateConnecting:
		return "TurnVK — подключается…"
	case engine.StateCaptcha:
		return "TurnVK — VK просит пройти проверку"
	case engine.StateFailed:
		return "TurnVK — ошибка подключения"
	}
	return "TurnVK"
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
	must(w.Bind("tvkSetCloseQuits", func(on bool) {
		a.mu.Lock()
		a.s.CloseQuits = on
		a.save()
		a.mu.Unlock()
		a.push()
	}))
	must(w.Bind("tvkSetStats", func(on bool) {
		a.mu.Lock()
		a.s.NoStats = !on
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
	must(w.Bind("tvkSetAutostart", func(on bool) error {
		if err := setAutostart(on); err != nil {
			a.logf("start with Windows: %v", err)
			a.push()
			return fmt.Errorf("не получилось: %v", err)
		}
		a.mu.Lock()
		a.s.Autostart = on
		a.save()
		a.mu.Unlock()
		if on {
			a.logf("start with Windows: on")
		} else {
			a.logf("start with Windows: off")
		}
		a.push()
		return nil
	}))
	must(w.Bind("tvkSetSplit", a.setSplit))
	must(w.Bind("tvkApplyMode", func(mode string) {
		a.mu.Lock()
		r := split.ApplyMode(a.s.Split, mode)
		a.mu.Unlock()
		a.setSplit(r)
	}))
	must(w.Bind("tvkExplain", func(target, app string) (split.Explanation, error) {
		return a.explain(target, app)
	}))
	must(w.Bind("tvkFailures", func() []split.Failure {
		a.mu.Lock()
		rt := a.router
		a.mu.Unlock()
		if rt == nil {
			return nil
		}
		return rt.Failures()
	}))
	must(w.Bind("tvkForgetFailures", func() {
		a.mu.Lock()
		rt := a.router
		a.mu.Unlock()
		if rt != nil {
			rt.ForgetFailures()
		}
	}))
	must(w.Bind("tvkNormDomain", func(s string) (string, error) {
		d, err := split.NormalizeDomain(s)
		if err != nil {
			return "", fmt.Errorf("«%s» — не имя сайта: %v", strings.TrimSpace(s), err)
		}
		return d, nil
	}))
	must(w.Bind("tvkNormList", func(s string) (string, error) {
		return split.NormalizeList(s)
	}))
	must(w.Bind("tvkListNames", func(kind string) []string {
		if kind == "geoip" {
			return a.listNames(split.GeoIPFile)
		}
		return a.listNames(split.GeoSiteFile)
	}))
	must(w.Bind("tvkUpdateLists", func() error {
		a.mu.Lock()
		e := a.eng
		a.mu.Unlock()
		if e == nil {
			return errors.New("списки скачиваются через VPN: сначала подключитесь")
		}
		go a.updateLists(e, true)
		return nil
	}))
	must(w.Bind("tvkHistory", func() []split.Conn {
		a.mu.Lock()
		rt := a.router
		a.mu.Unlock()
		if rt == nil {
			return nil
		}
		return rt.History(400)
	}))
	must(w.Bind("tvkForgetHistory", func() {
		a.mu.Lock()
		rt := a.router
		a.mu.Unlock()
		if rt != nil {
			rt.ForgetHistory()
		}
	}))
	must(w.Bind("tvkConns", func() []split.Conn {
		a.mu.Lock()
		rt := a.router
		a.mu.Unlock()
		if rt == nil {
			return nil
		}
		rt.Watch()
		return rt.Conns(400)
	}))
	must(w.Bind("tvkPick", func(folder bool) {
		go func() {
			path := pickPath(w.Window(), folder)
			if path != "" {
				a.eval("onPicked", map[string]any{"path": path, "folder": folder})
			}
		}()
	}))
	must(w.Bind("tvkReport", func() { go a.report() }))
	must(w.Bind("tvkPing", func() { go a.ping() }))
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

// setSplit saves new split tunneling rules and applies them at once.
func (a *app) setSplit(r split.Rules) {
	r.Normalize()
	a.mu.Lock()
	old := a.s.Split
	a.s.Split = r
	a.save()
	rt, e := a.router, a.eng
	eff, _ := a.effective()
	a.mu.Unlock()
	if rt != nil {
		rt.SetRules(eff)
		// New answers for names the rules now treat differently.
		byName := len(r.Domains) > 0 || len(old.Domains) > 0 || len(r.Lists) > 0 || len(old.Lists) > 0
		if old.On != r.On && byName || !sameDomains(old, r) || !slices.Equal(old.Lists, r.Lists) {
			split.FlushDNS()
		}
	}
	if !sameLists(old, r) {
		go func() {
			a.loadLists()
			a.updateLists(e, false) // a list from a file not downloaded yet
		}()
	}
	a.logf("split tunneling: %s", describeSplit(r))
	a.push()
}

// describeSplit sums the rules up for the log (program names, not paths:
// paths hold the user's name).
func describeSplit(r split.Rules) string {
	if !r.On {
		return "off"
	}
	var direct, vpn []string
	for _, x := range r.Apps {
		if x.Off {
			continue
		}
		n := filepath.Base(x.Path)
		if x.Folder {
			n += `\`
		}
		if x.Children {
			n += "+"
		}
		if x.Route == split.Direct {
			direct = append(direct, n)
		} else {
			vpn = append(vpn, n)
		}
	}
	for _, d := range r.Domains {
		if d.Off {
			continue
		}
		if d.Route == split.Direct {
			direct = append(direct, "site "+d.Domain)
		} else {
			vpn = append(vpn, "site "+d.Domain)
		}
	}
	for _, l := range r.Lists {
		if l.Off {
			continue
		}
		if l.Route == split.Direct {
			direct = append(direct, l.List)
		} else {
			vpn = append(vpn, l.List)
		}
	}
	return fmt.Sprintf("on, others %s, LAN direct %v, direct: %v, VPN: %v", r.Default, r.LAN, direct, vpn)
}

// sameDomains: the rules by name are the same (on, off, routes).
func sameDomains(a, b split.Rules) bool {
	if len(a.Domains) != len(b.Domains) {
		return false
	}
	for i := range a.Domains {
		if a.Domains[i] != b.Domains[i] {
			return false
		}
	}
	return true
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
	var v *winvpn.VPN
	v, err = winvpn.New(a.logf, func() {
		a.mu.Lock()
		cur := a.eng
		a.mu.Unlock()
		if cur != nil && cur == e {
			cur.Reconnect("the network changed")
			go a.networkChanged(v)
		}
	})
	if err != nil {
		return err
	}
	v.Debug = debugRun
	e, err = engine.New(engine.Config{
		Link: l, DeviceID: a.devID, Sessions: a.s.Sessions, Mode: wrap.ParseMode(a.s.Obfs),
		Net:     &netx.Net{DNS: netx.DefaultDNS, Protect: v.Protect},
		Captcha: a.captcha,
		VKCache: a.vkCache,
		Logf:    a.logf,
		NoStats: a.s.NoStats,
		Client:  "TurnVK " + version + " windows",
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
	a.netKind, a.netName = v.Network()
	rules, _ := a.effective()
	open := func(c *engine.WGConfig) (tun.Device, error) {
		dev, err := v.Open(c)
		if err != nil {
			return nil, err
		}
		always := []netip.Prefix{c.Address.Masked()}
		for _, d := range c.DNS {
			if d.Is4() {
				always = append(always, netip.PrefixFrom(d, 32))
			}
		}
		var dns []netip.Addr
		for _, d := range c.DNS {
			if d.Is4() {
				dns = append(dns, d)
			}
		}
		a.mu.Lock()
		lists := a.lists.loaded
		a.mu.Unlock()
		rt := split.New(dev, split.Options{
			Protect: v.Protect, Owner: split.NewOwner(), AlwaysVPN: always, DNS: dns, Fake: a.fake,
			// Sites sent direct are resolved past the tunnel, as TurnVK
			// resolves VK's names.
			Resolver: (&netx.Net{DNS: netx.DefaultDNS, Protect: v.Protect}).Resolver(),
			Lists:    lists,
			Addr:     c.Address.Addr(),
			Logf:     a.logf,
		}, rules)
		a.mu.Lock()
		if a.eng == e {
			a.router = rt
			// Rules changed while connecting.
			rules, _ = a.effective()
		}
		a.mu.Unlock()
		rt.SetRules(rules)
		if rules.On {
			a.logf("split tunneling: %s", describeSplit(rules))
			if len(rules.Domains) > 0 || len(rules.Lists) > 0 {
				// Answers cached before connecting would bypass the rules.
				split.FlushDNS()
			}
		}
		return rt, nil
	}
	go func() {
		err := e.Start(ctx, open)
		if err == nil {
			go a.selfCheck(e, l.Host)
			go a.keepListsFresh(e)
			<-e.Done()
			err = e.Err()
		}
		a.mu.Lock()
		a.remember(e)
		mine := a.eng == e
		if mine {
			a.eng, a.vpn, a.cancel, a.router = nil, nil, nil, nil
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
			split.FlushDNS() // placeholders mean nothing without TurnVK
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
	a.eng, a.vpn, a.cancel, a.lastErr, a.health, a.router = nil, nil, nil, "", "", nil
	a.mu.Unlock()
	if e == nil {
		return stopped
	}
	a.logf("disconnecting")
	go func() {
		cancel()
		e.Stop()
		v.Close()
		split.FlushDNS() // placeholders mean nothing without TurnVK
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

// effective: the split rules for the network the computer is on; a.mu is
// held.
func (a *app) effective() (split.Rules, string) {
	if a.eng == nil {
		return a.s.Split, ""
	}
	return split.ForNetwork(a.s.Split, a.netKind, a.netName)
}

// networkChanged applies the rules for the new network (the Wi-Fi's name
// takes Windows a moment after the switch).
func (a *app) networkChanged(v *winvpn.VPN) {
	for _, wait := range []time.Duration{2 * time.Second, 5 * time.Second} {
		time.Sleep(wait)
		kind, name := v.Network()
		a.mu.Lock()
		if a.vpn != v {
			a.mu.Unlock()
			return
		}
		same := kind == a.netKind && name == a.netName
		a.netKind, a.netName = kind, name
		eff, key := a.effective()
		rt := a.router
		a.mu.Unlock()
		if same {
			continue
		}
		if rt != nil {
			rt.SetRules(eff)
			split.FlushDNS()
		}
		if key != "" {
			a.logf("network %s: split mode %s", kind, split.ModeOf(eff))
		}
		a.push()
	}
}
