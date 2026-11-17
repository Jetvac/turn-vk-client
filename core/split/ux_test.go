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

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func TestModes(t *testing.T) {
	r := DefaultRules()
	r.Apps = []AppRule{{Path: `C:\g.exe`, Route: Direct}}
	if m := ModeOf(r); m != ModeVPN {
		t.Fatalf("off: %s", m)
	}
	b := ApplyMode(r, ModeBlocked)
	if m := ModeOf(b); m != ModeBlocked || !b.On || b.Default != Direct || len(b.Lists) != 2 || len(b.Apps) != 1 {
		t.Fatalf("blocked: %s %+v", m, b)
	}
	ru := ApplyMode(b, ModeRussia)
	if m := ModeOf(ru); m != ModeRussia || ru.Default != VPN || len(ru.Domains) != 3 {
		t.Fatalf("russia: %s %+v", m, ru)
	}
	if len(b.Domains) != 0 {
		t.Fatal("ApplyMode changed its argument")
	}
	ru.Lists[2].Off = true // geoip:ru
	if m := ModeOf(ru); m != ModeCustom {
		t.Fatalf("custom: %s", m)
	}
	if o := ApplyMode(ru, ModeVPN); o.On || len(o.Lists) != 4 {
		t.Fatalf("vpn: %+v", o)
	}
	if o := ApplyMode(ru, ModeRussia); ModeOf(o) != ModeRussia {
		t.Fatal("russia again")
	}
}

func TestExplain(t *testing.T) {
	dir := writeLists(t)
	r := Rules{On: true, Default: VPN, LAN: true,
		Apps:    []AppRule{{Path: `C:\Games\game.exe`, Route: Direct}},
		Domains: []DomainRule{{Domain: "su", Route: Direct}},
		Lists:   []ListRule{{List: "geoip:ru", Route: Direct}, {List: "geosite:youtube", Route: VPN}, {List: "geosite:netflix", Route: VPN}}}
	l, _ := LoadLists(dir, r.Lists)
	for _, c := range []struct {
		target, app string
		addrs       []netip.Addr
		route       Route
		why, note   string
	}{
		{"https://forum.game.su/page?x=1", "", nil, Direct, "все сайты .su", "попробует через VPN"},
		{"www.youtube.com", `C:\Games\game.exe`, nil, VPN, "список geosite:youtube", ""},
		{"example.com", `C:\Games\game.exe`, nil, Direct, "правило для game.exe", ""},
		{"example.com", "", nil, VPN, "нет правила для сайта: всё остальное идёт через VPN", "Адрес сайта не известен"},
		{"example.com", "", []netip.Addr{netip.MustParseAddr("5.8.1.1")}, Direct, "список geoip:ru", ""},
		{"5.8.1.1", "", nil, Direct, "список geoip:ru", ""},
		{"192.168.1.1", "", nil, Direct, "локальная сеть", ""},
	} {
		e, err := Explain(r, l, c.target, c.app, c.addrs)
		if err != nil || e.Route != c.route || e.Why != c.why || !strings.Contains(e.Note, c.note) {
			t.Errorf("%s/%s: %+v %v", c.target, c.app, e, err)
		}
		if !strings.Contains(e.Note, "geosite:netflix") && !strings.HasPrefix(c.target, "192.") {
			t.Errorf("%s: the missing list is not noted: %q", c.target, e.Note)
		}
	}
	if _, err := Explain(r, l, "not a site!", "", nil); err == nil {
		t.Error("garbage explained")
	}
	r.On = false
	if e, _ := Explain(r, l, "game.su", "", nil); e.Route != VPN {
		t.Errorf("off: %+v", e)
	}
}

// A site sent direct that drops the TLS hello opens through the VPN, and
// its next connection goes there at once.
func TestRetryThroughVPN(t *testing.T) {
	// Direct: a server that reads the hello and hangs up (as blocking does).
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { c.Read(make([]byte, 4096)); c.Close() }()
		}
	}()
	port := l.Addr().(*net.TCPAddr).AddrPort().Port()
	extraSniffPort = port
	defer func() { extraSniffPort = 0 }()
	g := newRig(t, Rules{On: true, Default: Direct}, withSites)
	farServer(t, g, port) // the same site through the VPN echoes
	hello := clientHello(t, "cdn.blocked.example.net")
	try := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := gonet.DialContextTCP(ctx, g.pc, far(netip.AddrPortFrom(lo, port)), ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write(hello)
		got := make([]byte, len(hello))
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, hello) {
			t.Fatalf("echo: %v", err)
		}
	}
	try()
	cs := g.r.Conns(5)
	if len(cs) != 1 || cs[0].Route != VPN || cs[0].Why != whyRetried {
		t.Fatalf("conns %+v", cs)
	}
	fs := g.r.Failures()
	if len(fs) != 1 || fs[0].Rule != "example.net" || !fs[0].OK || !strings.Contains(fs[0].Why, "TLS") {
		t.Fatalf("failures %+v", fs)
	}
	time.Sleep(50 * time.Millisecond)
	try()
	found := false
	for _, c := range g.r.Conns(5) {
		found = found || c.Why == whyFailed
	}
	if !found {
		t.Fatalf("second try: %+v", g.r.Conns(5))
	}
	// Once a rule sends the site through the VPN, it is not offered.
	g.r.SetRules(Rules{On: true, Default: Direct, Domains: []DomainRule{{Domain: "example.net", Route: VPN}}})
	if fs := g.r.Failures(); len(fs) != 0 {
		t.Fatalf("offered still: %+v", fs)
	}
}

// With retrying off, a site that hangs up stays hung up.
func TestNoRetry(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { c.Read(make([]byte, 4096)); c.Close() }()
		}
	}()
	port := l.Addr().(*net.TCPAddr).AddrPort().Port()
	extraSniffPort = port
	defer func() { extraSniffPort = 0 }()
	g := newRig(t, Rules{On: true, Default: Direct, NoRetry: true}, withSites)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, g.pc, far(netip.AddrPortFrom(lo, port)), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(clientHello(t, "x.example.net"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 10)); err == nil || n > 0 {
		t.Fatalf("read %d, %v", n, err)
	}
	if len(g.r.Failures()) != 0 {
		t.Fatal("noted a failure")
	}
}
