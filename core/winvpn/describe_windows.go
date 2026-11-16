//go:build windows

package winvpn

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Describe lists the computer's network state for a diagnostic report:
// Windows, the network TurnVK's own traffic leaves through, the TurnVK
// adapter, other VPNs and the routes that decide where traffic goes. v may
// be nil (not connected).
func Describe(v *VPN) []string {
	var out []string
	add := func(f string, a ...any) { out = append(out, fmt.Sprintf(f, a...)) }
	vi := windows.RtlGetVersion()
	add("windows: %d.%d.%d, administrator: %v", vi.MajorVersion, vi.MinorVersion, vi.BuildNumber, Elevated())
	if other := OtherVPN(); other != "" {
		add("another VPN takes the traffic: %s", other)
	} else {
		add("another VPN: none found")
	}
	i4 := defaultInterface(windows.AF_INET, 0)
	i6 := defaultInterface(windows.AF_INET6, 0)
	add("internet goes through (without TurnVK): IPv4 %s, IPv6 %s", ifName(i4), ifName(i6))
	if v != nil {
		add("TurnVK's routes are bound to: IPv4 %s, IPv6 %s", ifName(v.if4.Load()), ifName(v.if6.Load()))
	}

	// Adapters that are up, with addresses and DNS.
	ifs, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeGateways)
	if err == nil {
		for _, a := range ifs {
			if a.OperStatus != winipcfg.IfOperStatusUp || a.IfType == winipcfg.IfTypeSoftwareLoopback {
				continue
			}
			var addrs, dns, gw []string
			for u := a.FirstUnicastAddress; u != nil; u = u.Next {
				if ap, ok := netip.AddrFromSlice(u.Address.IP()); ok {
					addrs = append(addrs, fmt.Sprintf("%s/%d", ap.Unmap(), u.OnLinkPrefixLength))
				}
			}
			for d := a.FirstDNSServerAddress; d != nil; d = d.Next {
				dns = append(dns, d.Address.IP().String())
			}
			for g := a.FirstGatewayAddress; g != nil; g = g.Next {
				gw = append(gw, g.Address.IP().String())
			}
			tag := ""
			if isOurs(a.LUID) {
				tag = " [TurnVK]"
			}
			add("adapter %d %q%s (%s, type %d): MTU %d, addresses %s, gateway %s, DNS %s",
				a.IfIndex, a.FriendlyName(), tag, a.Description(), a.IfType, a.MTU,
				join(addrs), join(gw), join(dns))
		}
	}

	// Routes that cover much of the internet: they decide which adapter
	// gets the traffic.
	for _, fam := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		rows, err := winipcfg.GetIPForwardTable2(fam)
		if err != nil {
			continue
		}
		type rt struct {
			p      netip.Prefix
			ifi    uint32
			metric uint32
		}
		var list []rt
		counts := map[uint32]int{}
		for i := range rows {
			r := &rows[i]
			p := r.DestinationPrefix.Prefix()
			if !p.IsValid() || p.Bits() > 8 {
				continue
			}
			if p.Addr().Is4() {
				if a := p.Addr().As4(); p.Bits() > 0 && (a[0] >= 224 || a[0] == 127) {
					continue
				}
			} else if p.Bits() > 0 && p.Addr().As16()[0] == 0xff {
				continue
			}
			counts[r.InterfaceIndex]++
			if p.Bits() <= 1 {
				list = append(list, rt{p, r.InterfaceIndex, r.Metric})
			}
		}
		sort.Slice(list, func(i, j int) bool { return list[i].p.String() < list[j].p.String() })
		for _, r := range list {
			add("route %s via %s, metric %d", r.p, ifName(r.ifi), r.metric)
		}
		for ifi, n := range counts {
			if n > 2 {
				add("%s has %d wide routes (/2../8) for IPv%d: it takes traffic past broader routes", ifName(ifi), n, map[bool]int{true: 4, false: 6}[fam == windows.AF_INET])
			}
		}
	}
	return out
}

func ifName(i uint32) string {
	if i == 0 {
		return "none"
	}
	luid, err := winipcfg.LUIDFromIndex(i)
	if err != nil {
		return fmt.Sprintf("#%d", i)
	}
	r, err := luid.Interface()
	if err != nil {
		return fmt.Sprintf("#%d", i)
	}
	return fmt.Sprintf("#%d %q", i, r.Alias())
}

func join(s []string) string {
	if len(s) == 0 {
		return "-"
	}
	return strings.Join(s, " ")
}
