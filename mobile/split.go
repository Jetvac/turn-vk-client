//go:build linux || android

package mobile

// Split tunneling on Android: the same rules as on Windows (apps by
// package name, sites, lists). Android keeps the apps it can out of the
// tunnel itself (AppPlan); the rest enters, and the router in front of
// WireGuard decides connection by connection, finding the app by its user
// ID (Platform.OwnerUID).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/Jetvac/turn-vk-client/core/engine"
	"github.com/Jetvac/turn-vk-client/core/netx"
	"github.com/Jetvac/turn-vk-client/core/split"
)

const listsEvery = 12 * time.Hour

// splitLog writes to the app's log (set by Start).
var splitLog = func(string) {}

var sp = struct {
	mu     sync.Mutex
	rules  split.Rules
	router *split.Router
	fake   *split.Fake
	lists  *split.Lists
	busy   bool
	err    string
	names  map[string][]string
}{rules: split.DefaultRules(), fake: split.NewFake()}

// SetSplit sets the rules (JSON, as on Windows: on, default, lan, apps
// with package names as paths, domains, lists) and applies them to new
// connections at once. It returns the rules as kept (cleaned up). Changes
// to which apps Android keeps out (AppPlan) need a reconnect.
func SetSplit(rulesJSON string) (string, error) {
	r := split.DefaultRules()
	if strings.TrimSpace(rulesJSON) != "" {
		if err := json.Unmarshal([]byte(rulesJSON), &r); err != nil {
			return "", err
		}
	}
	r.Normalize()
	sp.mu.Lock()
	old := sp.rules
	sp.rules = r
	rt := sp.router
	sp.mu.Unlock()
	if rt != nil {
		rt.SetRules(r)
	}
	if !sameListNames(old, r) {
		go loadLists()
		go updateLists(currentEngine(), false)
	}
	b, err := json.Marshal(r)
	return string(b), err
}

func sameListNames(a, b split.Rules) bool {
	key := func(r split.Rules) []string {
		var out []string
		for _, l := range r.Lists {
			if !l.Off {
				out = append(out, l.List)
			}
		}
		slices.Sort(out)
		return out
	}
	return slices.Equal(key(a), key(b))
}

// AppPlan returns, as JSON {"mode":"disallow"|"allow","apps":[...]}, which
// apps the VPN interface should keep out ("disallow") or let in ("allow")
// under the current rules. With "allow" and no apps, only the app itself
// should be let in (nothing else goes through the VPN).
func AppPlan() string {
	sp.mu.Lock()
	r := sp.rules
	sp.mu.Unlock()
	b, _ := json.Marshal(split.PlanApps(r))
	return string(b)
}

// NormDomain cleans up a site's name as typed ("" and an error when it is
// not one).
func NormDomain(s string) (string, error) {
	d, err := split.NormalizeDomain(s)
	if err != nil {
		return "", fmt.Errorf("«%s» — не имя сайта: %v", strings.TrimSpace(s), err)
	}
	return d, nil
}

// NormList checks a list's name ("geoip:ru", "geosite:youtube").
func NormList(s string) (string, error) { return split.NormalizeList(s) }

// Conns returns the current connections as JSON (newest first), while
// connected; asking keeps the list filling for a while.
func Conns() string {
	sp.mu.Lock()
	rt := sp.router
	sp.mu.Unlock()
	if rt == nil {
		return "[]"
	}
	rt.Watch()
	b, _ := json.Marshal(rt.Conns(300))
	return string(b)
}

// wrapTun puts the router in front of WireGuard.
func wrapTun(dev tun.Device, c *engine.WGConfig, p Platform, protect func(uintptr) error) tun.Device {
	always := []netip.Prefix{c.Address.Masked()}
	var dns []netip.Addr
	for _, d := range c.DNS {
		if d.Is4() {
			always = append(always, netip.PrefixFrom(d, 32))
			dns = append(dns, d)
		}
	}
	owner := &split.UIDOwner{
		Logf: func(f string, a ...any) { p.Log(fmt.Sprintf(f, a...)) },
		UID: func(proto uint8, l, r netip.AddrPort) int {
			return p.OwnerUID(int(proto), l.Addr().String(), int(l.Port()), r.Addr().String(), int(r.Port()))
		},
		Names: func(uid int) []string {
			var out []string
			for _, n := range strings.Split(p.PackagesForUID(uid), ",") {
				if n = strings.TrimSpace(n); n != "" {
					out = append(out, n)
				}
			}
			return out
		},
	}
	sp.mu.Lock()
	rules, lists := sp.rules, sp.lists
	sp.mu.Unlock()
	rt := split.New(dev, split.Options{
		Protect: protect, Owner: owner, AlwaysVPN: always, DNS: dns, Fake: sp.fake, Addr: c.Address.Addr(),
		// Sites sent direct are resolved past the tunnel, as VK's names.
		Resolver: (&netx.Net{DNS: netx.DefaultDNS, Protect: protect}).Resolver(),
		Self:     uint32(os.Getuid()),
		Lists:    lists,
		Logf:     func(f string, a ...any) { p.Log(fmt.Sprintf(f, a...)) },
	}, rules)
	sp.mu.Lock()
	sp.router = rt
	rules = sp.rules // changed meanwhile
	sp.mu.Unlock()
	rt.SetRules(rules)
	if len(split.NeededFiles(rules.Lists)) > 0 {
		rt.UsePump() // the lists come through the tunnel (DialVPN)
	}
	return rt
}

func dropRouter() {
	sp.mu.Lock()
	sp.router = nil
	sp.mu.Unlock()
}

// --- lists ---

func listsDir() string {
	mu.Lock()
	d := dataDir
	mu.Unlock()
	if d == "" {
		return ""
	}
	return filepath.Join(d, "lists")
}

func loadLists() {
	dir := listsDir()
	sp.mu.Lock()
	rules := slices.Clone(sp.rules.Lists)
	sp.mu.Unlock()
	if dir == "" {
		return
	}
	l, _ := split.LoadLists(dir, rules)
	sp.mu.Lock()
	sp.lists = l
	rt := sp.router
	sp.mu.Unlock()
	if rt != nil {
		rt.SetLists(l)
	}
}

// LoadLists reads the downloaded lists the rules name (call once SetSplit
// and SetDataDir are set, off the main thread).
func LoadLists() { loadLists() }

type listsView struct {
	Files   []split.ListFile `json:"files"`
	Busy    bool             `json:"busy"`
	Error   string           `json:"error"`
	Missing []string         `json:"missing"`
}

// ListsInfo returns the state of the lists as JSON: files (name, size,
// updated), busy, error, missing (lists the rules name that are not
// loaded).
func ListsInfo() string {
	dir := listsDir()
	sp.mu.Lock()
	v := listsView{Busy: sp.busy, Error: sp.err}
	for _, r := range sp.rules.Lists {
		if !r.Off && !sp.lists.Has(r.List) {
			v.Missing = append(v.Missing, r.List)
		}
	}
	sp.mu.Unlock()
	if dir != "" {
		v.Files = split.ListFiles(dir)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// ListNames returns the lists a downloaded file has ("geoip" or
// "geosite"), one per line.
func ListNames(kind string) string {
	file := split.GeoSiteFile
	if kind == "geoip" {
		file = split.GeoIPFile
	}
	sp.mu.Lock()
	n, ok := sp.names[file]
	sp.mu.Unlock()
	if !ok {
		dir := listsDir()
		if dir == "" {
			return ""
		}
		var err error
		if n, err = split.ListNames(filepath.Join(dir, file)); err != nil {
			return ""
		}
		sp.mu.Lock()
		if sp.names == nil {
			sp.names = map[string][]string{}
		}
		sp.names[file] = n
		sp.mu.Unlock()
	}
	return strings.Join(n, "\n")
}

// UpdateLists downloads the lists that changed, in the background (while
// connected; the app's own traffic goes around the tunnel, as its update
// checks do).
func UpdateLists() error {
	e := currentEngine()
	if e == nil {
		return errors.New("списки скачиваются, пока VPN подключён")
	}
	go updateLists(e, true)
	return nil
}

func currentEngine() *engine.Engine {
	mu.Lock()
	defer mu.Unlock()
	return current
}

func updateLists(e *engine.Engine, force bool) {
	if e == nil {
		return
	}
	dir := listsDir()
	sp.mu.Lock()
	files := split.NeededFiles(sp.rules.Lists)
	if sp.busy || dir == "" || len(files) == 0 {
		sp.mu.Unlock()
		return
	}
	sp.busy, sp.err = true, ""
	sp.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	go func() {
		select {
		case <-e.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	// Through the tunnel first: GitHub is often blocked or slowed on
	// Russian networks, where the app's own sockets go. Then directly.
	var clients []split.ListClient
	sp.mu.Lock()
	rt := sp.router
	sp.mu.Unlock()
	if rt != nil {
		clients = append(clients, split.ListClient{Via: "через VPN", C: &http.Client{
			Timeout:   10 * time.Minute,
			Transport: &http.Transport{DialContext: rt.VPNDialContext, TLSHandshakeTimeout: 20 * time.Second},
		}})
	}
	clients = append(clients, split.ListClient{Via: "напрямую", C: &http.Client{Timeout: 10 * time.Minute}})
	changed, err := split.UpdateLists(ctx, dir, files, force, clients...)
	cancel()

	sp.mu.Lock()
	sp.busy = false
	if err != nil {
		sp.err = err.Error()
	}
	for _, f := range changed {
		delete(sp.names, f)
	}
	sp.mu.Unlock()
	if err != nil {
		splitLog("списки: " + err.Error())
	}
	if len(changed) > 0 {
		splitLog("списки обновлены: " + strings.Join(changed, ", "))
		loadLists()
	}
}

// keepListsFresh updates the lists after connecting and every listsEvery
// while e stays connected.
func keepListsFresh(e *engine.Engine) {
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-e.Done():
			return
		case <-t.C:
		}
		updateLists(e, false)
		t.Reset(listsEvery)
	}
}

// ModeOf tells the mode the rules (JSON) are in: "vpn", "blocked",
// "russia" or "custom".
func ModeOf(rulesJSON string) string {
	r := split.DefaultRules()
	_ = json.Unmarshal([]byte(rulesJSON), &r)
	return split.ModeOf(r)
}

// ApplyMode returns the rules (JSON) put into a mode, without applying
// them (SetSplit does).
func ApplyMode(rulesJSON, mode string) (string, error) {
	r := split.DefaultRules()
	if strings.TrimSpace(rulesJSON) != "" {
		if err := json.Unmarshal([]byte(rulesJSON), &r); err != nil {
			return "", err
		}
	}
	b, err := json.Marshal(split.ApplyMode(r, mode))
	return string(b), err
}

// Explain tells, as JSON (split.Explanation), where a site or address
// would go from an app (its package; "" for any) under the current rules.
// While connected, the site's addresses are found through the VPN.
func Explain(target, app string) (string, error) {
	sp.mu.Lock()
	r, l, rt := sp.rules, sp.lists, sp.router
	sp.mu.Unlock()
	if l == nil && len(r.Lists) > 0 {
		loadLists()
		sp.mu.Lock()
		l = sp.lists
		sp.mu.Unlock()
	}
	var addrs []netip.Addr
	if rt != nil {
		if h, err := split.NormalizeDomain(target); err == nil && strings.Contains(h, ".") {
			if _, err := netip.ParseAddr(h); err != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				addrs, _ = rt.VPNResolver().LookupNetIP(ctx, "ip4", h)
				cancel()
			}
		}
	}
	e, err := split.Explain(r, l, target, app, addrs)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(e)
	return string(b), err
}

// Failures returns, as JSON, the sites that did not open direct lately
// and were opened through the VPN (split.Failure), while connected.
func Failures() string {
	sp.mu.Lock()
	rt := sp.router
	sp.mu.Unlock()
	if rt == nil {
		return "[]"
	}
	b, _ := json.Marshal(rt.Failures())
	if string(b) == "null" {
		return "[]"
	}
	return string(b)
}

// ForgetFailures clears that list.
func ForgetFailures() {
	sp.mu.Lock()
	rt := sp.router
	sp.mu.Unlock()
	if rt != nil {
		rt.ForgetFailures()
	}
}
