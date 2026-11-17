package split

// Ready-made modes: the usual setups in one choice. A mode sets where the
// other traffic goes and adds (or turns on) the lists it needs; the user's
// own rules for programs, sites and other lists stay as they are.

const (
	// ModeVPN: everything through the VPN (split tunneling off).
	ModeVPN = "vpn"
	// ModeBlocked: only what is blocked in Russia through the VPN, the
	// rest direct.
	ModeBlocked = "blocked"
	// ModeRussia: Russian sites and addresses direct, the rest through
	// the VPN.
	ModeRussia = "russia"
	// ModeCustom: the user's own rules.
	ModeCustom = "custom"
)

var modeLists = map[string][]ListRule{
	ModeBlocked: {{List: "geosite:ru-blocked", Route: VPN}, {List: "geoip:ru-blocked", Route: VPN}},
	ModeRussia:  {{List: "geoip:ru", Route: Direct}, {List: "geosite:category-ru", Route: Direct}},
}

var modeDomains = map[string][]DomainRule{
	ModeRussia: {{Domain: "ru", Route: Direct}, {Domain: "su", Route: Direct}, {Domain: "рф", Route: Direct}},
}

// ModeOf tells which mode the rules are in.
func ModeOf(r Rules) string {
	if !r.On {
		return ModeVPN
	}
	has := func(name string, route Route) bool {
		for _, l := range r.Lists {
			if l.List == name && l.Route == route && !l.Off {
				return true
			}
		}
		return false
	}
	def := r.Default
	if !def.valid() {
		def = VPN
	}
	switch {
	case def == Direct && has("geosite:ru-blocked", VPN):
		return ModeBlocked
	case def == VPN && has("geoip:ru", Direct):
		return ModeRussia
	}
	return ModeCustom
}

// ApplyMode puts the rules into a mode (ModeCustom: turns them on, as
// they are).
func ApplyMode(r Rules, mode string) Rules {
	r.Apps = append([]AppRule(nil), r.Apps...)
	r.Domains = append([]DomainRule(nil), r.Domains...)
	r.Lists = append([]ListRule(nil), r.Lists...)
	switch mode {
	case ModeVPN:
		r.On = false
		return r
	case ModeBlocked:
		r.Default = Direct
	case ModeRussia:
		r.Default = VPN
	}
	r.On = true
	r.LAN = r.LAN || mode != ModeCustom
	for _, want := range modeLists[mode] {
		found := false
		for i := range r.Lists {
			if r.Lists[i].List == want.List {
				r.Lists[i].Route, r.Lists[i].Off, found = want.Route, false, true
			}
		}
		if !found {
			r.Lists = append(r.Lists, want)
		}
	}
	for _, want := range modeDomains[mode] {
		found := false
		for i := range r.Domains {
			if r.Domains[i].Domain == want.Domain {
				r.Domains[i].Route, r.Domains[i].Off, found = want.Route, false, true
			}
		}
		if !found {
			r.Domains = append(r.Domains, want)
		}
	}
	return r
}
