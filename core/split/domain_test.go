package split

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{
		"https://www.Example.com/path?x=1": "example.com",
		"www.co":                           "www.co",
		"mail.example.com":                 "mail.example.com",
		"example.com/watch":                "example.com",
		".su":                              "su",
		"*.example.com":                    "example.com",
		"example.com:443":                  "example.com",
		"РФ":                               "рф",
		"xn--p1ai":                         "рф",
		"Пример.рф":                        "пример.рф",
	} {
		if got, err := NormalizeDomain(in); err != nil || got != want {
			t.Errorf("%q: %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "*", "a b.com", "a..b"} {
		if got, err := NormalizeDomain(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}

func TestDomainMatch(t *testing.T) {
	d := newDomains([]DomainRule{
		{Domain: "su", Route: Direct},
		{Domain: "example.com", Route: Direct},
		{Domain: "vpn.example.com", Route: VPN},
		{Domain: "рф", Route: Direct},
		{Domain: "off.org", Route: Direct, Off: true},
	})
	for name, want := range map[string]Route{
		"game.su":               Direct,
		"SU.":                   Direct,
		"example.com":           Direct,
		"www.example.com":       Direct,
		"a.vpn.example.com.":    VPN,
		"notexample.com":        "",
		"xn--e1afmkfd.xn--p1ai": Direct, // пример.рф
		"off.org":               "",
		"sub.ru":                "",
	} {
		var got Route
		if r := d.match(name); r != nil {
			got = r.Route
		}
		if got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
}

// --- through the router ---

var siteRules = Rules{On: true, Default: VPN, Domains: []DomainRule{
	{Domain: "su", Route: Direct},
	{Domain: "example.org", Route: VPN},
}}

// testResolver resolves every name to the test's far address (the local
// echo servers).
type testResolver struct{}

func (testResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{testFar}, nil
}

func withSites(o *Options) {
	o.Fake = NewFake()
	o.Resolver = testResolver{}
	o.DNS = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
}

// ask sends a DNS query from the computer and returns the answer (nil
// when it went to the VPN instead).
func (g *rig) ask(t *testing.T, name string, typ dnsmessage.Type) *dnsmessage.Message {
	t.Helper()
	srv := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 66, 67, 1}), Port: 53}
	c, err := gonet.DialUDP(g.pc, nil, &srv, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 77, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name + "."), Type: typ, Class: dnsmessage.ClassINET}}}
	b, _ := q.Pack()
	c.Write(b)
	c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return nil
	}
	var m dnsmessage.Message
	if err := m.Unpack(buf[:n]); err != nil || m.ID != 77 {
		t.Fatalf("answer: %v", err)
	}
	return &m
}

func TestDNSPlaceholders(t *testing.T) {
	g := newRig(t, siteRules, withSites)
	a := g.ask(t, "game.su", dnsmessage.TypeA)
	if a == nil || len(a.Answers) != 1 {
		t.Fatalf("A game.su: %+v", a)
	}
	ip := netip.AddrFrom4(a.Answers[0].Body.(*dnsmessage.AResource).A)
	if !isFake(ip) || a.Answers[0].Header.TTL != fakeTTL {
		t.Fatalf("address %s", ip)
	}
	if b := g.ask(t, "GAME.su", dnsmessage.TypeA); b == nil || netip.AddrFrom4(b.Answers[0].Body.(*dnsmessage.AResource).A) != ip {
		t.Fatal("the same name got another address")
	}
	if b := g.ask(t, "game.su", dnsmessage.TypeAAAA); b == nil || len(b.Answers) != 0 || b.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("AAAA: %+v", b)
	}
	if b := g.ask(t, canary, dnsmessage.TypeA); b == nil || b.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("canary: %+v", b)
	}
	// Names without a direct rule go to the VPN's DNS untouched.
	if g.ask(t, "example.org", dnsmessage.TypeA) != nil || g.ask(t, "other.com", dnsmessage.TypeA) != nil {
		t.Fatal("answered a name the VPN should resolve")
	}
	got := 0
	for len(g.vpn) > 0 {
		var p pkt
		if b := <-g.vpn; parse(b, &p) && p.key.dst.Port() == 53 {
			got++
		}
	}
	if got != 2 {
		t.Fatalf("%d queries reached the VPN, want 2", got)
	}
}

func placeholder(t *testing.T, g *rig, name string) netip.Addr {
	t.Helper()
	a := g.ask(t, name, dnsmessage.TypeA)
	if a == nil || len(a.Answers) != 1 {
		t.Fatalf("no address for %s", name)
	}
	return netip.AddrFrom4(a.Answers[0].Body.(*dnsmessage.AResource).A)
}

func TestSiteDirectTCP(t *testing.T) {
	g := newRig(t, siteRules, withSites)
	ip := placeholder(t, g, "game.su")
	addr := echoTCP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, g.pc, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(ip.As4()), Port: addr.Port()}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("hello"))
	buf := make([]byte, 5)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("echo: %q %v", buf[:n], err)
	}
	var found bool
	for _, cn := range g.r.Conns(10) {
		if cn.Host == "game.su" && cn.Route == Direct && cn.Why == "сайт su" {
			found = true
		}
	}
	if !found {
		t.Fatalf("conns %+v", g.r.Conns(10))
	}
}

func TestSiteDirectUDP(t *testing.T) {
	g := newRig(t, siteRules, withSites)
	ip := placeholder(t, g, "voice.game.su")
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
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
			srv.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	// A connected socket: the answer must come from the placeholder.
	fa := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(ip.As4()), Port: srv.LocalAddr().(*net.UDPAddr).AddrPort().Port()}
	c, err := gonet.DialUDP(g.pc, nil, &fa, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 100)
	for i := 0; i < 3; i++ { // the first packet waits for the name to resolve
		c.Write([]byte("ping"))
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := c.Read(buf); err == nil && bytes.Equal(buf[:n], []byte("ping")) {
			return
		}
	}
	t.Fatal("no answer from the placeholder")
}

// A site sent through the VPN by name, while other programs go direct: the
// router learns its address from the VPN's DNS answer.
func TestSiteThroughVPN(t *testing.T) {
	rules := siteRules
	rules.Default = Direct
	g := newRig(t, rules, withSites)
	site := netip.MustParseAddr("203.0.113.9")
	ans := dnsmessage.Message{Header: dnsmessage.Header{ID: 1, Response: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("video.example.org."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("video.example.org."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30},
			Body: &dnsmessage.AResource{A: site.As4()}}}}
	b, _ := ans.Pack()
	pk := udpPackets(netip.MustParseAddrPort("10.66.67.1:53"), netip.MustParseAddrPort("10.66.67.2:5353"), b, 1280, 0, 1)
	g.r.Write(pk, 0) // as WireGuard would
	if h := g.r.hostOf(site); h != "video.example.org" {
		t.Fatalf("host %q", h)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go gonet.DialContextTCP(ctx, g.pc, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(site.As4()), Port: 443}, ipv4.ProtocolNumber)
	// (The computer may first answer the DNS packet itself with an ICMP
	// error: nothing listens on its port.)
	for done := false; !done; {
		select {
		case b := <-g.vpn:
			var p pkt
			if !parse(b, &p) {
				continue
			}
			if p.key.dst.Addr() != site {
				t.Fatalf("to the VPN: %x", b)
			}
			done = true
		case <-time.After(2 * time.Second):
			t.Fatal("the site did not go through the VPN")
		}
	}
	if c := g.r.Conns(1); len(c) != 1 || c[0].Why != "сайт example.org" {
		t.Fatalf("conns %+v", c)
	}
}

// Browsers' encrypted DNS to the tunnel's DNS server is refused at once.
func TestDoHRefused(t *testing.T) {
	g := newRig(t, siteRules, withSites)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, err := gonet.DialContextTCP(ctx, g.pc, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 443}, ipv4.ProtocolNumber)
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("DoH: %v after %s", err, time.Since(start))
	}
	if len(g.vpn) != 0 {
		t.Fatal("DoH reached the VPN")
	}
}
