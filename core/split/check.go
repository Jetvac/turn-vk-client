package split

import (
	"strings"
)

// Checking the rules: which rule is beaten by another, which changes
// nothing, which contradicts another. The notes go under the rules in the
// apps.

// RuleNote is a note on one rule.
type RuleNote struct {
	// Kind: "app", "domain" or "list"; Key: the rule's path, site or list.
	Kind   string `json:"kind"`
	Key    string `json:"key"`
	Folder bool   `json:"folder,omitempty"`
	// Warn: the rule does nothing or is beaten; otherwise it is an
	// explanation (an exception, what beats it sometimes).
	Warn bool   `json:"warn,omitempty"`
	Text string `json:"text"`
}

func routeWords(r Route) string {
	if r == Direct {
		return "напрямую"
	}
	return "через VPN"
}

// CheckRules finds the notes for the rules (with the rules on).
func CheckRules(r Rules) []RuleNote {
	r.Normalize()
	if !r.On {
		return nil
	}
	var out []RuleNote
	note := func(kind, key string, folder, warn bool, text string) {
		out = append(out, RuleNote{Kind: kind, Key: key, Folder: folder, Warn: warn, Text: text})
	}
	other := func(x Route) Route {
		if x == Direct {
			return VPN
		}
		return Direct
	}
	var apps []AppRule
	for _, a := range r.Apps {
		if !a.Off {
			apps = append(apps, a)
		}
	}
	var doms []DomainRule
	for _, d := range r.Domains {
		if !d.Off {
			doms = append(doms, d)
		}
	}
	var siteLists, ipLists []ListRule
	for _, l := range r.Lists {
		if l.Off {
			continue
		}
		if strings.HasPrefix(l.List, geositePrefix) {
			siteLists = append(siteLists, l)
		} else {
			ipLists = append(ipLists, l)
		}
	}
	appsRouted := func(route Route) int {
		n := 0
		for _, a := range apps {
			if a.Route == route {
				n++
			}
		}
		return n
	}
	sitesRouted := func(route Route) int {
		n := 0
		for _, d := range doms {
			if d.Route == route {
				n++
			}
		}
		for _, l := range siteLists {
			if l.Route == route {
				n++
			}
		}
		return n
	}

	// Sites.
	for _, d := range doms {
		var parent *DomainRule
		for i := range doms {
			p := &doms[i]
			if p.Domain != d.Domain && strings.HasSuffix(d.Domain, "."+p.Domain) && (parent == nil || len(p.Domain) > len(parent.Domain)) {
				parent = p
			}
		}
		switch {
		case parent != nil && parent.Route == d.Route:
			note("domain", d.Domain, false, true, "лишнее: правило для "+parent.Domain+" уже отправляет его "+routeWords(d.Route))
		case parent != nil:
			note("domain", d.Domain, false, false, "исключение из правила для "+parent.Domain)
		case r.AppsOnly:
			note("domain", d.Domain, false, false, "действует только в программах, выбранных для VPN")
		case d.Route == r.Default && appsRouted(other(d.Route)) == 0 && sitesRouted(other(d.Route)) == 0:
			note("domain", d.Domain, false, true, "ничего не меняет: всё остальное и так идёт "+routeWords(d.Route))
		}
	}

	// Programs.
	for _, a := range apps {
		var folder *AppRule
		n := normPath(a.Path)
		for i := range apps {
			f := &apps[i]
			fn := normPath(f.Path)
			if f.Folder && fn != n && strings.HasPrefix(n, fn+`\`) && (folder == nil || len(fn) > len(normPath(folder.Path))) {
				folder = f
			}
		}
		switch {
		case r.AppsOnly && a.Route == Direct && folder == nil:
			note("app", a.Path, a.Folder, true, "ничего не меняет: программы, не выбранные для VPN, и так идут напрямую")
			continue
		case folder != nil && folder.Route == a.Route:
			note("app", a.Path, a.Folder, true, "лишнее: правило для папки "+baseName(folder.Path)+" уже отправляет её "+routeWords(a.Route))
			continue
		case folder != nil:
			note("app", a.Path, a.Folder, false, "исключение из правила для папки "+baseName(folder.Path))
		case !r.AppsOnly && a.Route == r.Default:
			beats := 0
			for _, l := range ipLists {
				if l.Route != a.Route {
					beats++
				}
			}
			if beats == 0 {
				note("app", a.Path, a.Folder, true, "ничего не меняет: остальные программы и так идут "+routeWords(a.Route))
				continue
			}
		}
		if n := sitesRouted(other(a.Route)); n > 0 {
			note("app", a.Path, a.Folder, false, "кроме сайтов, которые правила для сайтов и списки отправляют "+routeWords(other(a.Route))+": они сильнее правил для программ")
		}
	}

	// Lists.
	for _, l := range r.Lists {
		if l.Off {
			continue
		}
		site := strings.HasPrefix(l.List, geositePrefix)
		switch {
		case r.AppsOnly && site:
			note("list", l.List, false, false, "действует только в программах, выбранных для VPN")
		case r.AppsOnly:
			note("list", l.List, false, true, "ничего не меняет: списки адресов не действуют, когда через VPN идут только выбранные программы")
		case !site && l.Route == r.Default:
			note("list", l.List, false, true, "ничего не меняет: всё остальное и так идёт "+routeWords(l.Route))
		case site && l.Route == r.Default && appsRouted(other(l.Route)) == 0:
			note("list", l.List, false, true, "ничего не меняет: всё остальное и так идёт "+routeWords(l.Route))
		case site && l.Route == Direct:
			for _, o := range siteLists {
				if o.Route == VPN {
					note("list", l.List, false, false, "сайт, который есть и в "+o.List+", пойдёт через VPN: при совпадении побеждает VPN")
					break
				}
			}
		case !site && l.Route == Direct:
			for _, o := range ipLists {
				if o.Route == VPN {
					note("list", l.List, false, false, "адрес, который есть и в "+o.List+", пойдёт через VPN: при совпадении побеждает VPN")
					break
				}
			}
		}
	}
	return out
}
