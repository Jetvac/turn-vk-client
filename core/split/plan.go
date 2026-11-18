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
}

// PlanApps works the plan out from the rules.
func PlanApps(r Rules) AppPlan {
	r.Normalize()
	if !r.On {
		return AppPlan{Mode: "disallow"}
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
	return AppPlan{Mode: "disallow", Apps: direct}
}
