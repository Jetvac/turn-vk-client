package split

// AppPlan says which apps Android itself keeps out of the tunnel (or lets
// in), set when the VPN interface is created. Apps the system keeps out
// cost nothing: their traffic never reaches TurnVK. An app can be kept out
// only when no rule could pull its traffic back into the VPN; otherwise it
// enters the tunnel and the router decides, connection by connection.
type AppPlan struct {
	// Mode: "disallow" — every app enters except Apps; "allow" — only Apps
	// enter.
	Mode string   `json:"mode"`
	Apps []string `json:"apps"`
	// Games: game apps are kept out too ("games direct"), unless only
	// chosen apps enter.
	Games bool `json:"games,omitempty"`
	// Ru: Russian apps (IsRuApp) are kept out too, except RuIn, which the
	// user's own rules send through the VPN (ruapps.go).
	Ru   bool     `json:"ru,omitempty"`
	RuIn []string `json:"ruIn,omitempty"`
}

// PlanApps works the plan out from the rules.
func PlanApps(r Rules) AppPlan {
	r.Normalize()
	if !r.On {
		return AppPlan{Mode: "disallow", Games: r.Games, Ru: !r.RuVPN}
	}
	// Sites beat the rules for programs, so a site sent through the VPN
	// reaches into apps sent direct. Address lists only refine the
	// others: they reach into the default.
	var vpnSites, vpnAddrs bool
	for _, d := range r.Domains {
		vpnSites = vpnSites || !d.Off && d.Route == VPN
	}
	for _, l := range r.Lists {
		if l.Off || l.Route != VPN {
			continue
		}
		if len(l.List) > len(geositePrefix) && l.List[:len(geositePrefix)] == geositePrefix {
			vpnSites = true
		} else {
			vpnAddrs = true
		}
	}
	var direct, vpn []string
	for _, a := range r.Apps {
		if a.Off || a.Folder {
			continue
		}
		if a.Route == Direct {
			direct = append(direct, a.Path)
		} else {
			vpn = append(vpn, a.Path)
		}
	}
	if r.AppsOnly || r.Default == Direct && !vpnSites && !vpnAddrs {
		return AppPlan{Mode: "allow", Apps: vpn}
	}
	if vpnSites {
		direct = nil
	}
	// Game apps go out even then: a game's traffic is mostly its servers'
	// addresses, and the lowest ping is the point. Russian apps too: inside
	// the tunnel they see the VPN and learn its exit address.
	p := AppPlan{Mode: "disallow", Apps: direct, Games: r.Games, Ru: !r.RuVPN}
	if p.Ru {
		for _, a := range vpn {
			if IsRuApp(a) {
				p.RuIn = append(p.RuIn, a)
			}
		}
	}
	return p
}
