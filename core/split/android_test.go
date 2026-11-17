package split

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestPlanApps(t *testing.T) {
	apps := []AppRule{{Path: "com.bank", Route: Direct}, {Path: "org.telegram", Route: VPN}, {Path: "com.off", Route: Direct, Off: true}}
	for _, c := range []struct {
		name string
		r    Rules
		mode string
		want []string
	}{
		{"off", Rules{Apps: apps}, "disallow", nil},
		{"vpn by default", Rules{On: true, Default: VPN, Apps: apps}, "disallow", []string{"com.bank"}},
		{"direct sites only", Rules{On: true, Default: VPN, Apps: apps, Domains: []DomainRule{{Domain: "ru", Route: Direct}}}, "disallow", []string{"com.bank"}},
		// A site sent through the VPN reaches into apps sent direct.
		{"vpn site", Rules{On: true, Default: VPN, Apps: apps, Lists: []ListRule{{List: "geosite:ru-blocked", Route: VPN}}}, "disallow", nil},
		{"direct by default", Rules{On: true, Default: Direct, Apps: apps}, "allow", []string{"org.telegram"}},
		// An address list through the VPN reaches into the others.
		{"direct, vpn addresses", Rules{On: true, Default: Direct, Apps: apps, Lists: []ListRule{{List: "geoip:telegram", Route: VPN}}}, "disallow", []string{"com.bank"}},
		{"direct, vpn site", Rules{On: true, Default: Direct, Apps: apps, Domains: []DomainRule{{Domain: "youtube.com", Route: VPN}}}, "disallow", nil},
	} {
		p := PlanApps(c.r)
		if p.Mode != c.mode || !slices.Equal(p.Apps, c.want) {
			t.Errorf("%s: %+v", c.name, p)
		}
	}
}

// Packages sharing a user ID: a rule for any of them applies.
func TestAltNames(t *testing.T) {
	r := Rules{On: true, Default: VPN, Apps: []AppRule{{Path: "com.shared.two", Route: Direct}}}
	d := newMatcher(r, nil, nil).decide(netip.MustParseAddr("8.8.8.8"), "", &Proc{PID: 10123, Path: "com.shared.one", Alt: []string{"com.shared.two"}})
	if d.Route != Direct {
		t.Fatalf("%+v", d)
	}
}

func TestProcNet(t *testing.T) {
	dir := t.TempDir()
	tcp := filepath.Join(dir, "tcp6")
	// 10.66.67.2:40000 -> 93.184.216.34:443, uid 10123, as an IPv4-mapped
	// IPv6 socket; and a listening socket of another app.
	os.WriteFile(tcp, []byte(`  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000243420A:9C40 0000000000000000FFFF000022D8B85D:01BB 01 00000000:00000000 00:00000000 00000000 10123        0 1 1
   1: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 10200        0 2 1
`), 0o644)
	local, remote := netip.MustParseAddrPort("10.66.67.2:40000"), netip.MustParseAddrPort("93.184.216.34:443")
	if uid := scanProcNet(tcp, protoTCP, local, remote); uid != 10123 {
		t.Fatalf("uid %d", uid)
	}
	if uid := scanProcNet(tcp, protoTCP, local, netip.MustParseAddrPort("1.1.1.1:443")); uid != -1 {
		t.Fatalf("another connection: uid %d", uid)
	}
	udp := filepath.Join(dir, "udp")
	os.WriteFile(udp, []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  5: 00000000:D431 00000000:0000 07 00000000:00000000 00:00000000 00000000 10321        0 3 2 0 0
`), 0o644)
	if uid := scanProcNet(udp, protoUDP, netip.MustParseAddrPort("10.66.67.2:54321"), netip.MustParseAddrPort("8.8.8.8:53")); uid != 10321 {
		t.Fatalf("udp uid %d", uid)
	}
	o := &UIDOwner{
		UID:   func(uint8, netip.AddrPort, netip.AddrPort) int { return 10500 },
		Names: func(uid int) []string { return []string{"a.b", "a.c"} },
	}
	if p := o.Lookup(protoTCP, local, remote, false); p == nil || p.PID != 10500 || p.Path != "a.b" || !slices.Equal(p.Alt, []string{"a.c"}) {
		t.Fatalf("lookup %+v", p)
	}
}
