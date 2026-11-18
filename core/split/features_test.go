package split

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

func TestHistory(t *testing.T) {
	g := newRig(t, direct)
	addr := echoTCP(t)
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := gonet.DialContextTCP(ctx, g.pc, far(addr), ipv4.ProtocolNumber)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("hi"))
		io.ReadFull(c, make([]byte, 2))
		c.Close()
	}
	time.Sleep(200 * time.Millisecond)
	// What expire does 30 s after they closed.
	g.r.mu.Lock()
	for k, f := range g.r.flows {
		g.r.dropLocked(k, f)
	}
	g.r.mu.Unlock()
	h := g.r.History(10)
	if len(h) != 1 || h[0].N != 3 || h[0].Route != Direct || !h[0].Closed || h[0].Name != "game.exe" {
		t.Fatalf("history %+v", h)
	}
	g.r.ForgetHistory()
	if len(g.r.History(10)) != 0 {
		t.Fatal("not forgotten")
	}
}

func TestAppsOnly(t *testing.T) {
	r := ApplyMode(Rules{Apps: []AppRule{{Path: `C:\T\tg.exe`, Route: VPN}, {Path: `C:\G\game.exe`, Route: Direct}},
		Domains: []DomainRule{{Domain: "ru", Route: Direct}, {Domain: "youtube.com", Route: VPN}}}, ModeApps)
	if ModeOf(r) != ModeApps || !r.AppsOnly || r.Default != Direct {
		t.Fatalf("mode %s %+v", ModeOf(r), r)
	}
	m := newMatcher(r, nil, nil)
	ip := netip.MustParseAddr("8.8.8.8")
	for _, c := range []struct {
		host, app string
		want      Route
	}{
		{"x.com", `C:\T\tg.exe`, VPN},
		{"mail.ru", `C:\T\tg.exe`, Direct}, // a rule for sites inside a chosen program
		{"youtube.com", `C:\B\chrome.exe`, Direct},
		{"x.com", `C:\G\game.exe`, Direct},
		{"x.com", "", Direct},
	} {
		var p *Proc
		if c.app != "" {
			p = &Proc{Path: c.app}
		}
		if d := m.decide(ip, c.host, p); d.Route != c.want {
			t.Errorf("%s %s: %+v", c.host, c.app, d)
		}
	}
	if p := PlanApps(Rules{On: true, AppsOnly: true, Apps: []AppRule{{Path: "org.telegram", Route: VPN}}, Domains: []DomainRule{{Domain: "x.com", Route: VPN}}}); p.Mode != "allow" || len(p.Apps) != 1 {
		t.Fatalf("plan %+v", p)
	}
	if o := ApplyMode(r, ModeBlocked); o.AppsOnly || ModeOf(o) != ModeBlocked {
		t.Fatalf("leaving: %+v", o)
	}
}

func TestCheckRules(t *testing.T) {
	r := Rules{On: true, Default: VPN,
		Apps:    []AppRule{{Path: `C:\Games`, Folder: true, Route: Direct}, {Path: `C:\Games\a.exe`, Route: Direct}, {Path: `C:\Games\b.exe`, Route: VPN}, {Path: `C:\x.exe`, Route: VPN}},
		Domains: []DomainRule{{Domain: "ru", Route: Direct}, {Domain: "mail.ru", Route: Direct}, {Domain: "vk.ru", Route: VPN}},
		Lists:   []ListRule{{List: "geoip:de", Route: VPN}, {List: "geosite:category-ru", Route: Direct}, {List: "geosite:ru-blocked", Route: VPN}}}
	got := map[string]RuleNote{}
	for _, n := range CheckRules(r) {
		k := n.Kind + "|" + n.Key
		if o, ok := got[k]; ok {
			n.Text = o.Text + "; " + n.Text
		}
		got[k] = n
	}
	for key, want := range map[string]string{
		"domain|mail.ru":           "лишнее",
		"domain|vk.ru":             "исключение",
		`app|C:\Games\a.exe`:       "лишнее",
		`app|C:\Games\b.exe`:       "исключение",
		`app|C:\x.exe`:             "ничего не меняет",
		`app|C:\Games`:             "сильнее",
		"list|geoip:de":            "ничего не меняет",
		"list|geosite:category-ru": "побеждает VPN",
	} {
		if n, ok := got[key]; !ok || !strings.Contains(n.Text, want) {
			t.Errorf("%s: %+v (want %q)", key, n, want)
		}
	}
	if n, ok := got["domain|ru"]; ok {
		t.Errorf("ru: %+v", n)
	}
}

func TestForNetwork(t *testing.T) {
	r := Rules{On: true, Default: VPN, Domains: []DomainRule{{Domain: "su", Route: Direct}},
		Networks: []NetRule{{Network: "wifi:Home", Mode: ModeBlocked}, {Network: "mobile", Mode: ModeVPN}, {Network: "wifi", Mode: ModeRussia}, {Network: "bogus", Mode: ModeVPN}}}
	r.Normalize()
	if len(r.Networks) != 3 {
		t.Fatalf("networks %+v", r.Networks)
	}
	if e, n := ForNetwork(r, NetWiFi, "Home"); ModeOf(e) != ModeBlocked || n != "wifi:Home" || len(e.Domains) != 1 {
		t.Fatalf("home: %s %s %+v", ModeOf(e), n, e)
	}
	if e, n := ForNetwork(r, NetWiFi, "Cafe"); ModeOf(e) != ModeRussia || n != "wifi" {
		t.Fatalf("cafe: %s %s", ModeOf(e), n)
	}
	if e, _ := ForNetwork(r, NetMobile, ""); e.On {
		t.Fatal("mobile: on")
	}
	if e, n := ForNetwork(r, NetWired, ""); n != "" || ModeOf(e) != ModeCustom {
		t.Fatalf("wired: %s %s", ModeOf(e), n)
	}
	off := r
	off.On = false
	if e, _ := ForNetwork(off, NetWiFi, "Home"); e.On {
		t.Fatal("off stays off")
	}
	names := map[string]bool{}
	for _, l := range AllLists(r) {
		names[l.List] = true
	}
	for _, want := range []string{"geosite:ru-blocked", "geoip:ru-blocked", "geoip:ru", "geosite:category-ru"} {
		if !names[want] {
			t.Errorf("lists: no %s", want)
		}
	}
}

// QUIC sent direct that gets no answer goes through the VPN.
func TestQUICRetry(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close() // answers nothing
	port := srv.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	extraSniffPort = port
	defer func() { extraSniffPort = 0 }()
	g := newRig(t, Rules{On: true, Default: Direct})
	fa := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(testFar.As4()), Port: port}
	c, err := gonet.DialUDP(g.pc, nil, &fa, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("initial"))
	time.Sleep(quicRetryWait + 500*time.Millisecond)
	select {
	case b := <-g.vpn:
		var p pkt
		if !parse(b, &p) || string(p.payload) != "initial" {
			t.Fatalf("to the VPN: %x", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the first packet was not resent through the VPN")
	}
	cs := g.r.Conns(5)
	if len(cs) != 1 || cs[0].Route != VPN || cs[0].Why != whyRetried || !cs[0].Retried {
		t.Fatalf("conns %+v", cs)
	}
	if fs := g.r.Failures(); len(fs) != 1 || !strings.Contains(fs[0].Why, "QUIC") {
		t.Fatalf("failures %+v", fs)
	}
	c.Write([]byte("next"))
	select {
	case <-g.vpn:
	case <-time.After(2 * time.Second):
		t.Fatal("later packets do not go through the VPN")
	}
	// A new QUIC connection to it goes through the VPN at once...
	c2, err := gonet.DialUDP(g.pc, nil, &fa, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	c2.Write([]byte("again"))
	select {
	case <-g.vpn:
	case <-time.After(time.Second):
		t.Fatal("second connection not through the VPN")
	}
	// ...but TCP to it still tries direct.
	if g.r.failedBefore("", testFar) {
		t.Fatal("a QUIC failure sends TCP through the VPN")
	}
}

// IPv6 sent direct works; IPv6 for the VPN is refused at once.
func TestIPv6(t *testing.T) {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 here:", err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	port := l.Addr().(*net.TCPAddr).AddrPort().Port()
	g := newRig(t, direct)
	fa := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom16(testFar6.As16()), Port: port}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, g.pc, fa, ipv6.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	msg := bytes.Repeat([]byte("v6 "), 10000)
	go c.Write(msg)
	got := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo: %v", err)
	}
	c.Close()

	srv, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		buf := make([]byte, 2000)
		for {
			n, from, err := srv.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			srv.WriteToUDPAddrPort(append([]byte("re:"), buf[:n]...), from)
		}
	}()
	ua := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom16(testFar6.As16()), Port: srv.LocalAddr().(*net.UDPAddr).AddrPort().Port()}
	uc, err := gonet.DialUDP(g.pc, nil, &ua, ipv6.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.Write([]byte("ping"))
	buf := make([]byte, 100)
	uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := uc.Read(buf); err != nil || string(buf[:n]) != "re:ping" {
		t.Fatalf("udp: %q %v", buf[:n], err)
	}
	if n := len(g.vpn); n != 0 {
		t.Fatalf("%d packets went to the VPN", n)
	}

	// Another program's (through the VPN): a reset, not a wait.
	g.r.SetRules(Rules{On: true, Default: VPN, Apps: []AppRule{{Path: `C:\Other\x.exe`, Route: Direct}}})
	start := time.Now()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if _, err := gonet.DialContextTCP(ctx2, g.pc, fa, ipv6.ProtocolNumber); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("IPv6 for the VPN: %v after %s", err, time.Since(start))
	}
}
