package split

import (
	"errors"
	"net/netip"
	"strings"
)

// Explanation answers "where would this go, and why?".
type Explanation struct {
	Route Route  `json:"route"`
	Why   string `json:"why"`
	// Host: the site's name as checked ("" for an address).
	Host string `json:"host,omitempty"`
	// Addr: the address checked, when known.
	Addr string `json:"addr,omitempty"`
	// Note: what could still change the answer.
	Note string `json:"note,omitempty"`
}

// Explain tells where a connection to target (a site's name, a link or an
// address) from the program app ("" for any; Windows: the .exe's path,
// Android: the package) would go under the rules. addrs are the site's
// addresses when known (resolved by the caller): lists of countries and
// addresses apply to them.
func Explain(r Rules, lists *Lists, target, app string, addrs []netip.Addr) (Explanation, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return Explanation{}, errors.New("введите сайт или адрес")
	}
	var host string
	var dsts []netip.Addr
	if a, err := netip.ParseAddr(strings.Trim(target, "[]")); err == nil {
		dsts = []netip.Addr{a.Unmap()}
	} else {
		h, err := NormalizeDomain(target)
		if err != nil {
			return Explanation{}, errors.New("«" + target + "» — не сайт и не адрес")
		}
		host = h
		if a, err := toASCII(h); err == nil {
			host = a
		}
		for _, a := range addrs {
			if a = a.Unmap(); a.Is4() && !isFake(a) {
				dsts = append(dsts, a)
			}
		}
	}
	var p *Proc
	if app = strings.TrimSpace(app); app != "" {
		p = &Proc{Path: app}
	}
	m := newMatcher(r, nil, lists)
	e := Explanation{Host: host}
	if host != "" {
		if u, err := NormalizeDomain(host); err == nil {
			e.Host = u
		}
	}
	if p != nil && ruOut(&r, app) {
		e.Route, e.Why = Direct, "российское приложение: не входит в VPN"
		return e, nil
	}
	if len(dsts) == 0 {
		d := m.decide(netip.Addr{}, host, p)
		e.Route, e.Why = d.Route, d.Why
		if r.On && len(m.ips) > 0 && d.Why == "остальные программы" {
			e.Note = "Адрес сайта не известен: если он есть в списке стран или адресов, путь будет по этому списку."
		}
	} else {
		d := m.decide(dsts[0], host, p)
		e.Route, e.Why, e.Addr = d.Route, d.Why, dsts[0].String()
		for _, a := range dsts[1:] {
			if o := m.decide(a, host, p); o.Route != d.Route {
				e.Note = "У сайта несколько адресов, и они идут разными путями (" + a.String() + ": " + o.Why + ")."
				break
			}
		}
	}
	if d, ok := strings.CutPrefix(e.Why, "сайт "); ok && !strings.Contains(d, ".") {
		e.Why = "все сайты ." + d
	}
	if e.Why == "остальные программы" {
		if p != nil {
			e.Why = "нет правила ни для сайта, ни для программы"
		} else {
			e.Why = "нет правила для сайта"
		}
		if r.Default == Direct {
			e.Why += ": всё остальное идёт напрямую"
		} else {
			e.Why += ": всё остальное идёт через VPN"
		}
	}
	var missing []string
	for _, l := range r.Lists {
		if r.On && !l.Off && !lists.Has(l.List) {
			missing = append(missing, l.List)
		}
	}
	if len(missing) > 0 {
		n := "Списки ещё не скачаны: " + strings.Join(missing, ", ") + "."
		if e.Note != "" {
			n = e.Note + " " + n
		}
		e.Note = n
	}
	if e.Route == Direct && r.On && !r.NoRetry && host != "" && !strings.HasPrefix(e.Why, "локальная") {
		n := "Если сайт не откроется напрямую, TurnVK попробует через VPN."
		if e.Note != "" {
			n = e.Note + " " + n
		}
		e.Note = n
	}
	return e, nil
}
