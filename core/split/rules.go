// Package split decides, connection by connection, which traffic goes
// through the VPN and which goes straight to the internet.
//
// All of the computer's traffic enters the TurnVK adapter (its routes take
// everything). The Router sits between the adapter and WireGuard and looks
// at the first packet of every new connection: which program opened it (by
// its local port), where it goes, and what the rules say. Connections for
// the VPN pass to WireGuard untouched. Direct ones are answered inside
// TurnVK and opened again on the physical network, through sockets bound to
// it, so they cannot loop back into the tunnel.
//
// The decision is made before the first packet leaves the computer, for
// every address a program uses, TCP and UDP alike: there is nothing to set
// up in advance and nothing slips past.
package split

import (
	"net/netip"
	"path/filepath"
	"strings"
)

// Route is where a connection goes.
type Route string

const (
	VPN    Route = "vpn"
	Direct Route = "direct"
)

func (r Route) valid() bool { return r == VPN || r == Direct }

// AppRule routes a program, or every program in a folder.
type AppRule struct {
	// Path of the .exe, or of the folder when Folder is set.
	Path   string `json:"path"`
	Folder bool   `json:"folder,omitempty"`
	// Children: the programs this one starts follow the rule too
	// (launchers, helpers, the game a launcher runs).
	Children bool  `json:"children,omitempty"`
	Route    Route `json:"route"`
	// Off keeps the rule without applying it.
	Off bool `json:"off,omitempty"`
}

// Rules are the user's settings.
type Rules struct {
	On bool `json:"on"`
	// Default is the route of everything no rule matches.
	Default Route `json:"default"`
	// LAN: private addresses (192.168.x.x, 10.x.x.x...) go direct.
	LAN  bool      `json:"lan"`
	Apps []AppRule `json:"apps"`
	// Domains route sites by name, whatever the program; they beat the
	// rules for programs ("everything .su direct", even from a browser
	// that goes through the VPN).
	Domains []DomainRule `json:"domains"`
	// Lists route whole lists: sites of a category (beside Domains) and
	// addresses of a country or a service (after the rules for programs:
	// they refine "the other programs").
	Lists []ListRule `json:"lists"`
	// NoRetry: a site sent direct that does not open is not tried again
	// through the VPN.
	NoRetry bool `json:"noRetry,omitempty"`
	// AppsOnly: only programs with a rule "through the VPN" use it;
	// everything else goes direct, whatever the rules for sites and lists
	// say (they apply inside those programs). On Android the other apps
	// do not even enter the tunnel.
	AppsOnly bool `json:"appsOnly,omitempty"`
	// Custom: the user chose "own rules", so the rules are not read back
	// as a ready-made mode even when they still hold its lists.
	Custom bool `json:"custom,omitempty"`
	// Networks switch the mode by the network the device is on
	// (network.go).
	Networks []NetRule `json:"networks,omitempty"`
}

// DefaultRules: off; when turned on, everything goes through the VPN except
// the local network.
func DefaultRules() Rules { return Rules{Default: VPN, LAN: true} }

// Normalize fixes what a hand-edited or older settings file may hold.
func (r *Rules) Normalize() {
	if !r.Default.valid() {
		r.Default = VPN
	}
	out := r.Apps[:0]
	seen := map[string]bool{}
	for _, a := range r.Apps {
		a.Path = strings.TrimSpace(a.Path)
		if a.Path == "" {
			continue
		}
		a.Path = filepath.Clean(a.Path)
		if !a.Route.valid() {
			a.Route = Direct
		}
		k := key(a.Path, a.Folder)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, a)
	}
	r.Apps = out
	dout := r.Domains[:0]
	dseen := map[string]bool{}
	for _, d := range r.Domains {
		n, err := NormalizeDomain(d.Domain)
		if err != nil || dseen[n] {
			continue
		}
		dseen[n] = true
		d.Domain = n
		if !d.Route.valid() {
			d.Route = Direct
		}
		dout = append(dout, d)
	}
	r.Domains = dout
	lout := r.Lists[:0]
	lseen := map[string]bool{}
	for _, l := range r.Lists {
		n, err := NormalizeList(l.List)
		if err != nil || lseen[n] {
			continue
		}
		lseen[n] = true
		l.List = n
		if !l.Route.valid() {
			l.Route = Direct
		}
		lout = append(lout, l)
	}
	r.Lists = lout
	nout := r.Networks[:0]
	nseen := map[string]bool{}
	for _, n := range r.Networks {
		n.Network = normNetwork(n.Network)
		if n.Network == "" || nseen[n.Network] || !validMode(n.Mode) {
			continue
		}
		nseen[n.Network] = true
		nout = append(nout, n)
	}
	r.Networks = nout
}

func key(path string, folder bool) string {
	k := normPath(path)
	if folder {
		return "d|" + k
	}
	return "f|" + k
}

// normPath makes paths comparable: Windows paths ignore case and either
// slash.
func normPath(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	p = strings.TrimRight(p, `\`)
	return strings.ToLower(p)
}

// baseName is the last element of a path, Windows' or not, on any system
// (filepath.Base keeps backslashes outside Windows).
func baseName(p string) string {
	p = strings.TrimRight(p, `\/`)
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// Proc is the program behind a connection.
type Proc struct {
	PID  uint32
	Path string // full path of the .exe ("" when Windows does not tell)
	// Parents: the paths of the programs that started this one, nearest
	// first (filled only when a rule needs them).
	Parents []string
	// Alt: other names of the same program (Android: the packages that
	// share its user ID); a rule for any of them applies.
	Alt []string
}

// Name is the .exe's file name.
func (p *Proc) Name() string {
	if p == nil || p.Path == "" {
		return ""
	}
	return baseName(p.Path)
}

// Decision is the route of a connection and why.
type Decision struct {
	Route Route
	// Why is the reason in the app's words (shown in the connections list).
	Why string
}

// matcher is Rules made quick to apply.
type matcher struct {
	rules  Rules
	exact  map[string]*AppRule // normalized .exe path
	folder []*AppRule          // longest path first
	norm   map[*AppRule]string
	kids   bool // some rule covers child processes
	vpn    []netip.Prefix
	dom    domains
	sites  []siteList
	ips    []ipList
	// byName: rules by site name exist (DNS is watched).
	byName bool
	// directSites: some site goes direct by name (placeholders, no DoH);
	// vpnSites: some site goes through the VPN by name.
	directSites bool
	vpnSites    bool
	// anyDirect: something goes direct beside programs (TurnVK's own
	// connections have to be told apart).
	anyDirect bool
	// retry: sites sent direct that do not open are tried through the VPN.
	retry bool
}

type siteList struct {
	rule *ListRule
	set  *SiteSet
}

type ipList struct {
	rule *ListRule
	set  *IPSet
}

var lanPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fc00::/7"),
}

func newMatcher(r Rules, alwaysVPN []netip.Prefix, lists *Lists) *matcher {
	r.Normalize()
	m := &matcher{rules: r, exact: map[string]*AppRule{}, norm: map[*AppRule]string{}, vpn: alwaysVPN}
	if r.On {
		m.retry = !r.NoRetry
		m.dom = newDomains(r.Domains)
		m.directSites = m.dom.hasDirect()
		for _, d := range m.dom {
			m.vpnSites = m.vpnSites || d.Route == VPN
		}
		m.anyDirect = m.directSites || r.Default == Direct || r.AppsOnly
		for i := range r.Lists {
			l := &r.Lists[i]
			if l.Off || lists == nil {
				continue
			}
			if s := lists.Site[l.List]; s != nil {
				m.sites = append(m.sites, siteList{l, s})
				m.directSites = m.directSites || l.Route == Direct
				m.vpnSites = m.vpnSites || l.Route == VPN
				m.anyDirect = m.anyDirect || l.Route == Direct
			}
			if s := lists.IP[l.List]; s != nil {
				m.ips = append(m.ips, ipList{l, s})
				m.anyDirect = m.anyDirect || l.Route == Direct
			}
		}
		m.byName = len(m.dom) > 0 || len(m.sites) > 0
	}
	for i := range r.Apps {
		a := &r.Apps[i]
		if a.Off {
			continue
		}
		n := normPath(a.Path)
		m.norm[a] = n
		if a.Children {
			m.kids = true
		}
		if a.Folder {
			m.folder = append(m.folder, a)
		} else {
			m.exact[n] = a
		}
	}
	// Longest folder first: a rule for a subfolder beats one for its parent.
	for i := 1; i < len(m.folder); i++ {
		for j := i; j > 0 && len(m.norm[m.folder[j]]) > len(m.norm[m.folder[j-1]]); j-- {
			m.folder[j], m.folder[j-1] = m.folder[j-1], m.folder[j]
		}
	}
	return m
}

// needsProc: rules about programs exist (so the owner of each connection
// has to be found).
func (m *matcher) needsProc() bool { return len(m.exact) > 0 || len(m.folder) > 0 }

// fixed decides what does not depend on the program: the tunnel's own
// addresses, the local network. ok is false when the program decides.
func (m *matcher) fixed(dst netip.Addr) (Decision, bool) {
	for _, p := range m.vpn {
		if p.Contains(dst) {
			return Decision{VPN, "адрес VPN"}, true
		}
	}
	if !m.rules.On {
		return Decision{VPN, "раздельное туннелирование выключено"}, true
	}
	if m.rules.LAN {
		for _, p := range lanPrefixes {
			if p.Contains(dst) {
				return Decision{Direct, "локальная сеть"}, true
			}
		}
	}
	return Decision{}, false
}

// decide routes a connection to dst (host: the site's name when known)
// of the program p (nil when unknown).
func (m *matcher) decide(dst netip.Addr, host string, p *Proc) Decision {
	if d, ok := m.fixed(dst); ok {
		return d
	}
	if m.rules.AppsOnly {
		// Only the chosen programs use the VPN; inside them the rules
		// for sites still apply.
		a, parent := m.appFor(p)
		if a == nil || a.Route != VPN {
			return Decision{Direct, whyNotChosen}
		}
		if d, ok := m.site(host); ok {
			return d
		}
		return Decision{VPN, m.why(a, parent)}
	}
	if d, ok := m.site(host); ok {
		return d
	}
	if a, parent := m.appFor(p); a != nil {
		return Decision{a.Route, m.why(a, parent)}
	}
	if d, ok := m.ipList(dst); ok {
		return d
	}
	return Decision{m.rules.Default, "остальные программы"}
}

// whyNotChosen: with only the chosen programs through the VPN, another
// program's connection.
const whyNotChosen = "программа не выбрана для VPN"

// appFor finds the rule for a program: its own, another name of it, or
// that of a program which started it (parent: that program's name).
func (m *matcher) appFor(p *Proc) (a *AppRule, parent string) {
	if p == nil || p.Path == "" {
		return nil, ""
	}
	if a := m.app(normPath(p.Path)); a != nil {
		return a, ""
	}
	for _, n := range p.Alt {
		if a := m.app(normPath(n)); a != nil {
			return a, ""
		}
	}
	for _, pp := range p.Parents {
		if a := m.app(normPath(pp)); a != nil && a.Children {
			return a, baseName(pp)
		}
	}
	return nil, ""
}

// site finds the rule for a site's name: the user's own sites first (the
// longest match), then the lists. When several lists hold a site, the VPN
// wins.
func (m *matcher) site(host string) (Decision, bool) {
	if host == "" {
		return Decision{}, false
	}
	if d := m.dom.match(host); d != nil {
		return Decision{d.Route, "сайт " + d.Domain}, true
	}
	var hit *ListRule
	for _, l := range m.sites {
		if (hit == nil || l.rule.Route == VPN) && l.set.Match(host) {
			hit = l.rule
			if hit.Route == VPN {
				break
			}
		}
	}
	if hit == nil {
		return Decision{}, false
	}
	return Decision{hit.Route, "список " + hit.List}, true
}

// ipList finds the list an address is in (the VPN wins, as for sites).
func (m *matcher) ipList(dst netip.Addr) (Decision, bool) {
	var hit *ListRule
	for _, l := range m.ips {
		if (hit == nil || l.rule.Route == VPN) && l.set.Contains(dst) {
			hit = l.rule
			if hit.Route == VPN {
				break
			}
		}
	}
	if hit == nil {
		return Decision{}, false
	}
	return Decision{hit.Route, "список " + hit.List}, true
}

// app finds the rule for a normalized .exe path: the program's own rule,
// then the closest folder.
func (m *matcher) app(n string) *AppRule {
	if a := m.exact[n]; a != nil {
		return a
	}
	for _, a := range m.folder {
		if strings.HasPrefix(n, m.norm[a]+`\`) {
			return a
		}
	}
	return nil
}

func (m *matcher) why(a *AppRule, parent string) string {
	s := "правило для " + baseName(a.Path)
	if a.Folder {
		s = "правило для папки " + baseName(a.Path)
	}
	if parent != "" {
		s += " (запущена из " + parent + ")"
	}
	return s
}
