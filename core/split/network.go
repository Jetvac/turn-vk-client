package split

import "strings"

// Rules by network: a mode for a kind of network (Wi-Fi, mobile, wired) or
// for one Wi-Fi network by its name. On a network with a rule, its mode
// applies on top of the user's rules (as choosing the mode would); on the
// others the rules apply as they are.

// Network kinds.
const (
	NetWiFi   = "wifi"
	NetMobile = "mobile"
	NetWired  = "wired"
	// netWiFiName prefixes a Wi-Fi network's name: "wifi:Home".
	netWiFiName = "wifi:"
)

// NetRule is the mode for a network.
type NetRule struct {
	// Network: "wifi", "mobile", "wired", or "wifi:<name>".
	Network string `json:"network"`
	Mode    string `json:"mode"`
	Off     bool   `json:"off,omitempty"`
}

func normNetwork(n string) string {
	n = strings.TrimSpace(n)
	if name, ok := strings.CutPrefix(n, netWiFiName); ok {
		if name = strings.TrimSpace(name); name == "" {
			return ""
		}
		return netWiFiName + name
	}
	switch n = strings.ToLower(n); n {
	case NetWiFi, NetMobile, NetWired:
		return n
	}
	return ""
}

// NetworkKey is the network rule's key for a Wi-Fi network's name.
func NetworkKey(kind, wifiName string) string {
	if kind == NetWiFi && strings.TrimSpace(wifiName) != "" {
		return netWiFiName + strings.TrimSpace(wifiName)
	}
	return kind
}

// ForNetwork returns the rules to apply on a network (kind: NetWiFi,
// NetMobile, NetWired or "" when unknown; wifiName when known) and the
// network rule used ("" for none). A rule for the Wi-Fi network's name
// beats the one for Wi-Fi in general. With the rules off, they stay off:
// the switch on the home screen turns everything off.
func ForNetwork(r Rules, kind, wifiName string) (Rules, string) {
	if !r.On || len(r.Networks) == 0 || kind == "" {
		return r, ""
	}
	var hit *NetRule
	keys := []string{NetworkKey(kind, wifiName), kind}
	for _, k := range keys {
		for i := range r.Networks {
			n := &r.Networks[i]
			if !n.Off && normNetwork(n.Network) == k && validMode(n.Mode) {
				hit = n
				break
			}
		}
		if hit != nil {
			break
		}
	}
	if hit == nil || hit.Mode == ModeCustom {
		if hit != nil {
			return r, hit.Network
		}
		return r, ""
	}
	return ApplyMode(r, hit.Mode), hit.Network
}

// AllLists: the lists the rules may use on any network (the lists to
// download).
func AllLists(r Rules) []ListRule {
	out := append([]ListRule(nil), r.Lists...)
	if !r.On {
		return out
	}
	for _, n := range r.Networks {
		if n.Off {
			continue
		}
	next:
		for _, l := range modeLists[n.Mode] {
			for i, o := range out {
				if o.List == l.List {
					if o.Off {
						out[i].Off = false
					}
					continue next
				}
			}
			out = append(out, l)
		}
	}
	return out
}

// NetworkName is a network rule's key in the app's words.
func NetworkName(key string) string {
	if name, ok := strings.CutPrefix(key, netWiFiName); ok {
		return "Wi-Fi «" + name + "»"
	}
	switch key {
	case NetWiFi:
		return "Wi-Fi"
	case NetMobile:
		return "мобильная сеть"
	case NetWired:
		return "кабель"
	}
	return key
}
