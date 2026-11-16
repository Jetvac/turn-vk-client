//go:build windows

// Package winvpn runs the tunnel as a system VPN on Windows: a Wintun
// adapter carries all of the computer's traffic, while the engine's own
// sockets (VK API, DNS for VK names, TURN) are bound to the physical network
// with IP_UNICAST_IF, so they do not loop into the tunnel. It needs
// administrator rights and wintun.dll next to the program.
package winvpn

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/Jetvac/turn-vk-client/core/engine"
)

// AdapterName is the network adapter's name in Windows.
const AdapterName = "TurnVK"

// A fixed GUID: Windows keeps one network profile for the adapter instead of
// creating "TurnVK 2", "TurnVK 3"... on every connection.
var adapterGUID = windows.GUID{Data1: 0x7d3a1c55, Data2: 0x5b0e, Data3: 0x4f6a, Data4: [8]byte{0x9b, 0x21, 0x74, 0x76, 0x6b, 0x77, 0x64, 0x74}}

// The tunnel carries IPv4 only. An IPv6 address and routes on the adapter
// send IPv6 traffic there too, where it is dropped: without them it would go
// past the VPN. Unique local addresses rank below IPv4 in address selection,
// so programs keep using IPv4.
var ula = netip.MustParsePrefix("fd74:766b:7764:7474::2/64")

const (
	ipUnicastIf   = 31 // IP_UNICAST_IF
	ipv6UnicastIf = 31 // IPV6_UNICAST_IF
)

func init() {
	tun.WintunTunnelType = AdapterName
	tun.WintunStaticRequestedGUID = &adapterGUID
}

// VPN tracks the physical network the engine's sockets go through.
type VPN struct {
	if4, if6 atomic.Uint32 // interface index of the default route, 0: none
	luid     atomic.Uint64 // the adapter, 0 before Open
	logf     func(string, ...any)
	changed  func()

	mu    sync.Mutex
	timer *time.Timer
	cb    *winipcfg.RouteChangeCallback
}

// New finds the physical network. changed is called (after the routes
// settle) when the computer switches to another network, so that the engine
// reconnects through it.
func New(logf func(string, ...any), changed func()) (*VPN, error) {
	v := &VPN{logf: logf, changed: changed}
	v.update(false)
	if v.if4.Load() == 0 {
		return nil, errors.New("no network connection")
	}
	cb, err := winipcfg.RegisterRouteChangeCallback(func(_ winipcfg.MibNotificationType, r *winipcfg.MibIPforwardRow2) {
		if r == nil || r.DestinationPrefix.PrefixLength > 8 || uint64(r.InterfaceLUID) == v.luid.Load() {
			return
		}
		v.mu.Lock()
		defer v.mu.Unlock()
		if v.timer != nil {
			v.timer.Stop()
		}
		v.timer = time.AfterFunc(time.Second, func() { v.update(true) })
	})
	if err != nil {
		return nil, fmt.Errorf("watching routes: %w", err)
	}
	v.cb = cb
	return v, nil
}

// Close stops watching the routes.
func (v *VPN) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.timer != nil {
		v.timer.Stop()
	}
	if v.cb != nil {
		v.cb.Unregister()
		v.cb = nil
	}
}

func (v *VPN) update(notify bool) {
	skip := winipcfg.LUID(v.luid.Load())
	i4 := defaultInterface(windows.AF_INET, skip)
	i6 := defaultInterface(windows.AF_INET6, skip)
	if i4 == 0 {
		// Offline for now: keep the old binding until a network is back.
		return
	}
	old := v.if4.Swap(i4)
	v.if6.Store(i6)
	if notify && old != i4 {
		v.logf("network: interface %d -> %d", old, i4)
		if v.changed != nil {
			v.changed()
		}
	}
}

// Where the engine's traffic would go without the tunnel: public addresses
// (VK's DNS servers) stand for the whole internet.
var (
	probe4 = netip.MustParseAddr("77.88.8.8")
	probe6 = netip.MustParseAddr("2a02:6b8::feed:ff")
)

// defaultInterface returns the index of the interface Windows would send
// internet traffic through, leaving out the TurnVK adapter (skip), or 0. It
// follows the most specific route, so another VPN that takes all traffic
// (with two /1 routes, say) is used as the system uses it: TurnVK's traffic
// then goes through it.
func defaultInterface(family winipcfg.AddressFamily, skip winipcfg.LUID) uint32 {
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return 0
	}
	probe := probe4
	if family == windows.AF_INET6 {
		probe = probe6
	}
	var best uint32
	bestBits, bestMetric := -1, ^uint32(0)
	for i := range rows {
		r := &rows[i]
		p := r.DestinationPrefix.Prefix()
		if !p.IsValid() || !p.Contains(probe) || r.InterfaceLUID == skip || (skip == 0 && isOurs(r.InterfaceLUID)) {
			continue
		}
		if p.Bits() < bestBits {
			continue
		}
		ifr, err := r.InterfaceLUID.Interface()
		if err != nil || ifr.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		ipif, err := r.InterfaceLUID.IPInterface(family)
		if err != nil || !ipif.Connected {
			continue
		}
		m := r.Metric + ipif.Metric
		if p.Bits() > bestBits || m < bestMetric {
			best, bestBits, bestMetric = r.InterfaceIndex, p.Bits(), m
		}
	}
	return best
}

// isOurs: a TurnVK adapter left from an earlier run (before Open we don't
// know its LUID yet).
func isOurs(l winipcfg.LUID) bool {
	g, err := l.GUID()
	return err == nil && *g == adapterGUID
}

// Protect binds a socket to the physical network (engine's netx.Protector).
// Sockets are IPv4 or IPv6; the option of the other family fails, so one of
// the two is enough.
func (v *VPN) Protect(fd uintptr) error {
	i4 := v.if4.Load()
	if i4 == 0 {
		return nil
	}
	// IP_UNICAST_IF takes the index in network byte order.
	be := i4>>24 | i4>>8&0xff00 | i4<<8&0xff0000 | i4<<24
	err4 := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, int(be))
	var err6 error = errors.New("no IPv6 network")
	if i6 := v.if6.Load(); i6 != 0 {
		err6 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, ipv6UnicastIf, int(i6))
	}
	if err4 != nil && err6 != nil {
		return fmt.Errorf("binding a socket to the network: %w", err4)
	}
	return nil
}

// Open creates the adapter for the engine's tunnel settings (engine's
// TunFactory): address, routes for all traffic, DNS, MTU.
func (v *VPN) Open(c *engine.WGConfig) (tun.Device, error) {
	dev, err := tun.CreateTUN(AdapterName, c.MTU)
	if err != nil {
		return nil, fmt.Errorf("creating the network adapter: %w", err)
	}
	nt, ok := dev.(*tun.NativeTun)
	if !ok {
		dev.Close()
		return nil, errors.New("unexpected adapter type")
	}
	luid := winipcfg.LUID(nt.LUID())
	v.luid.Store(uint64(luid))
	if err := configure(luid, c); err != nil {
		dev.Close()
		return nil, err
	}
	return dev, nil
}

func configure(luid winipcfg.LUID, c *engine.WGConfig) error {
	addrs := []netip.Prefix{c.Address}
	if c.Address.Addr().Is4() {
		addrs = append(addrs, ula)
	}
	if err := luid.SetIPAddresses(addrs); err != nil {
		return fmt.Errorf("setting the address: %w", err)
	}

	allowed := c.AllowedIPs
	if len(allowed) == 0 {
		allowed = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	}
	var routes []*winipcfg.RouteData
	has6 := false
	add := func(p netip.Prefix) {
		nh := netip.IPv4Unspecified()
		if p.Addr().Is6() {
			nh, has6 = netip.IPv6Unspecified(), true
		}
		routes = append(routes, &winipcfg.RouteData{Destination: p.Masked(), NextHop: nh})
	}
	for _, p := range allowed {
		// Two halves instead of a default route: they beat the network's own
		// default route whatever its metric.
		if p.Bits() == 0 {
			lo, _ := p.Addr().Prefix(1)
			add(lo)
			hi := netip.MustParsePrefix("128.0.0.0/1")
			if p.Addr().Is6() {
				hi = netip.MustParsePrefix("8000::/1")
			}
			add(hi)
			continue
		}
		add(p)
	}
	if !has6 {
		add(netip.MustParsePrefix("::/1"))
		add(netip.MustParsePrefix("8000::/1"))
	}
	if err := luid.SetRoutes(routes); err != nil {
		return fmt.Errorf("setting routes: %w", err)
	}

	for _, fam := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		ipif, err := luid.IPInterface(fam)
		if err != nil {
			if fam == windows.AF_INET6 {
				continue // IPv6 is turned off on this computer
			}
			return fmt.Errorf("adapter settings: %w", err)
		}
		// The lowest metric: Windows asks the tunnel's DNS servers first.
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
		ipif.NLMTU = uint32(c.MTU)
		if fam == windows.AF_INET6 && ipif.NLMTU < 1280 {
			ipif.NLMTU = 1280
		}
		ipif.DadTransmits = 0
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		if err := ipif.Set(); err != nil && fam == windows.AF_INET {
			return fmt.Errorf("adapter settings: %w", err)
		}
	}

	dns := c.DNS
	if len(dns) == 0 {
		dns = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	var d4, d6 []netip.Addr
	for _, a := range dns {
		if a.Is4() {
			d4 = append(d4, a)
		} else {
			d6 = append(d6, a)
		}
	}
	if err := luid.SetDNS(windows.AF_INET, d4, nil); err != nil {
		return fmt.Errorf("setting DNS: %w", err)
	}
	_ = luid.SetDNS(windows.AF_INET6, d6, nil)
	return nil
}

// Elevated reports whether the program runs with administrator rights.
func Elevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// OtherVPN returns the name of another VPN adapter that takes the
// computer's internet traffic (v2RayTun, OpenVPN, WireGuard...), or "".
// With one running, TurnVK's two halves of the address space lose to its
// more specific routes: most traffic keeps going through that VPN while DNS
// goes to TurnVK, and programs break in odd ways.
func OtherVPN() string {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return ""
	}
	type ifc struct {
		broad  int  // routes /1../8 to public space
		virtDf bool // a default route on a virtual adapter
	}
	seen := map[winipcfg.LUID]*ifc{}
	virtual := map[winipcfg.LUID]bool{}
	isVirtual := func(l winipcfg.LUID) bool {
		v, ok := virtual[l]
		if !ok {
			if r, err := l.Interface(); err == nil {
				v = r.OperStatus == winipcfg.IfOperStatusUp &&
					(r.Type == winipcfg.IfTypePropVirtual || r.Type == winipcfg.IfTypeTunnel)
			}
			virtual[l] = v
		}
		return v
	}
	for i := range rows {
		r := &rows[i]
		p := r.DestinationPrefix.Prefix()
		if !p.IsValid() || p.Bits() > 8 || isOurs(r.InterfaceLUID) {
			continue
		}
		a := p.Addr().As4()
		if p.Bits() > 0 && (a[0] >= 224 || a[0] == 10 || a[0] == 127) {
			continue // multicast, reserved, private
		}
		if !isVirtual(r.InterfaceLUID) {
			continue
		}
		c := seen[r.InterfaceLUID]
		if c == nil {
			c = &ifc{}
			seen[r.InterfaceLUID] = c
		}
		if p.Bits() == 0 {
			c.virtDf = true
		} else {
			c.broad++
		}
	}
	for l, c := range seen {
		if c.virtDf || c.broad >= 2 {
			if r, err := l.Interface(); err == nil {
				if name := r.Alias(); name != "" {
					return name
				}
				return r.Description()
			}
			return "VPN"
		}
	}
	return ""
}
