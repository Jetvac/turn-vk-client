//go:build windows

package winvpn

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// AdapterState describes the adapter's IPv4 addresses and settings as
// Windows sees them (for the debug run).
func (v *VPN) AdapterState() []string {
	luid := winipcfg.LUID(v.luid.Load())
	if luid == 0 {
		return []string{"no adapter"}
	}
	var out []string
	if rows, err := winipcfg.GetUnicastIPAddressTable(windows.AF_INET); err == nil {
		for i := range rows {
			r := &rows[i]
			if r.InterfaceLUID != luid {
				// The same address on another interface confuses Windows.
				if a := r.Address.Addr(); a.IsValid() && v.isOurAddr(a.String()) {
					out = append(out, fmt.Sprintf("ALSO on interface %d: %s/%d dad %d", r.InterfaceIndex, a, r.OnLinkPrefixLength, r.DadState))
				}
				continue
			}
			out = append(out, fmt.Sprintf("address %s/%d dad %d prefix-origin %d suffix-origin %d skip-as-source %v valid %d", r.Address.Addr(), r.OnLinkPrefixLength, r.DadState, r.PrefixOrigin, r.SuffixOrigin, r.SkipAsSource, r.ValidLifetime))
		}
	} else {
		out = append(out, "addresses: "+err.Error())
	}
	if ipif, err := luid.IPInterface(windows.AF_INET); err == nil {
		out = append(out, fmt.Sprintf("ipv4 interface #%d: connected %v, metric %d, mtu %d, forwarding %v, weak-host send %v receive %v, dad-transmits %d",
			ipif.InterfaceIndex, ipif.Connected, ipif.Metric, ipif.NLMTU, ipif.ForwardingEnabled, ipif.WeakHostSend, ipif.WeakHostReceive, ipif.DadTransmits))
	} else {
		out = append(out, "ipv4 interface: "+err.Error())
	}
	if rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET); err == nil {
		host := false
		for i := range rows {
			p := rows[i].DestinationPrefix.Prefix()
			host = host || (p.Bits() == 32 && v.isOurAddr(p.Addr().String()))
		}
		if !host {
			out = append(out, "NO local route for "+v.addr4+"/32: Windows will drop replies to it")
		}
		for i := range rows {
			r := &rows[i]
			p := r.DestinationPrefix.Prefix()
			if p.Bits() == 32 && v.isOurAddr(p.Addr().String()) {
				out = append(out, fmt.Sprintf("route %s via interface %d next hop %s metric %d protocol %d", p, r.InterfaceIndex, r.NextHop.Addr(), r.Metric, r.Protocol))
			}
		}
	}
	return out
}

func (v *VPN) isOurAddr(a string) bool { return a == v.addr4 }
