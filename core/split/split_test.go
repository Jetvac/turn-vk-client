package split

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func TestMatcher(t *testing.T) {
	r := Rules{On: true, Default: VPN, LAN: true, Apps: []AppRule{
		{Path: `C:\Games\Wardogs`, Folder: true, Route: Direct},
		{Path: `C:\Games\Wardogs\Tools`, Folder: true, Route: VPN},
		{Path: `C:\Program Files\Steam\steam.exe`, Children: true, Route: Direct},
		{Path: `C:\Apps\Telegram.exe`, Route: Direct},
		{Path: `C:\Apps\Off.exe`, Route: Direct, Off: true},
	}}
	m := newMatcher(r, []netip.Prefix{netip.MustParsePrefix("10.66.67.0/24")}, nil)
	pub := netip.MustParseAddr("8.8.8.8")
	for _, c := range []struct {
		name string
		dst  netip.Addr
		p    *Proc
		want Route
	}{
		{"folder", pub, &Proc{Path: `c:/games/WARDOGS/Binaries/Win64/Game.exe`}, Direct},
		{"subfolder beats folder", pub, &Proc{Path: `C:\Games\Wardogs\Tools\crash.exe`}, VPN},
		{"not a prefix of a name", pub, &Proc{Path: `C:\Games\WardogsX\a.exe`}, VPN},
		{"exact", pub, &Proc{Path: `C:\Apps\telegram.exe`}, Direct},
		{"rule off", pub, &Proc{Path: `C:\Apps\Off.exe`}, VPN},
		{"child", pub, &Proc{Path: `D:\Lib\game.exe`, Parents: []string{`C:\Program Files\Steam\steam.exe`}}, Direct},
		{"grandchild", pub, &Proc{Path: `D:\Lib\x.exe`, Parents: []string{`D:\Lib\game.exe`, `C:\Program Files\Steam\steam.exe`}}, Direct},
		{"own rule beats parent", pub, &Proc{Path: `C:\Games\Wardogs\Tools\t.exe`, Parents: []string{`C:\Program Files\Steam\steam.exe`}}, VPN},
		{"unknown program", pub, nil, VPN},
		{"LAN", netip.MustParseAddr("192.168.1.10"), nil, Direct},
		{"the VPN's own network", netip.MustParseAddr("10.66.67.1"), &Proc{Path: `C:\Apps\Telegram.exe`}, VPN},
	} {
		if d := m.decide(c.dst, "", c.p); d.Route != c.want {
			t.Errorf("%s: %s (%s), want %s", c.name, d.Route, d.Why, c.want)
		}
	}
	r.On = false
	if d := newMatcher(r, nil, nil).decide(pub, "", &Proc{Path: `C:\Apps\Telegram.exe`}); d.Route != VPN {
		t.Errorf("rules off: %s", d.Route)
	}
	r.On, r.Default = true, Direct
	if d := newMatcher(r, nil, nil).decide(pub, "", &Proc{Path: `C:\x.exe`}); d.Route != Direct {
		t.Errorf("default direct: %s", d.Route)
	}
}

func TestNormalize(t *testing.T) {
	r := Rules{Default: "?", Apps: []AppRule{{Path: " "}, {Path: `C:\A\b.exe`}, {Path: `c:/a/B.EXE`, Route: VPN}, {Path: `C:\A`, Folder: true, Route: VPN}}}
	r.Normalize()
	if r.Default != VPN || len(r.Apps) != 2 || r.Apps[0].Route != Direct {
		t.Fatalf("%+v", r)
	}
}

func TestUDPPacketsFragments(t *testing.T) {
	src := netip.MustParseAddrPort("1.2.3.4:500")
	dst := netip.MustParseAddrPort("10.0.0.2:600")
	payload := bytes.Repeat([]byte("abcdefg"), 700) // 4900 bytes
	pkts := udpPackets(src, dst, payload, 1280, 0, 7)
	if len(pkts) != 4 {
		t.Fatalf("%d packets", len(pkts))
	}
	var data []byte
	for i, b := range pkts {
		if len(b) > 1280 || checksum(b[:20], 0) != 0 {
			t.Fatalf("packet %d: %d bytes, bad header", i, len(b))
		}
		ff := binary.BigEndian.Uint16(b[6:8])
		if int(ff&0x1fff)*8 != len(data) || (ff&0x2000 != 0) != (i < len(pkts)-1) {
			t.Fatalf("packet %d: flags %x", i, ff)
		}
		data = append(data, b[20:]...)
	}
	if !bytes.Equal(data[8:], payload) {
		t.Fatal("payload differs")
	}
	// The UDP checksum over the pseudo-header comes out zero.
	var ps uint32 = 0x0102 + 0x0304 + 0x0a00 + 0x0002 + protoUDP + uint32(len(data))
	if checksum(data, ps) != 0 {
		t.Fatal("bad UDP checksum")
	}
}

// --- the router between a simulated computer and a simulated WireGuard ---

type fakeTun struct {
	out    chan []byte // the computer's packets
	in     chan []byte // packets for the computer
	closed chan struct{}
	once   sync.Once
}

func newFakeTun() *fakeTun {
	return &fakeTun{out: make(chan []byte, 65536), in: make(chan []byte, 65536), closed: make(chan struct{})}
}

func (f *fakeTun) File() *os.File           { return nil }
func (f *fakeTun) MTU() (int, error)        { return 1280, nil }
func (f *fakeTun) Name() (string, error)    { return "fake", nil }
func (f *fakeTun) Events() <-chan tun.Event { return nil }
func (f *fakeTun) BatchSize() int           { return 1 }
func (f *fakeTun) Close() error             { f.once.Do(func() { close(f.closed) }); return nil }

func (f *fakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case b := <-f.out:
		sizes[0] = copy(bufs[0][offset:], b)
		return 1, nil
	case <-f.closed:
		return 0, os.ErrClosed
	}
}

func (f *fakeTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		select {
		case f.in <- append([]byte(nil), b[offset:]...):
		default:
		}
	}
	return len(bufs), nil
}

type fakeOwner struct{ path string }

func (o fakeOwner) Lookup(uint8, netip.AddrPort, netip.AddrPort, bool) *Proc {
	return &Proc{PID: 42, Path: o.path}
}

var me = netip.MustParseAddr("10.66.67.2")

// The simulated computer talks to 203.0.113.1, which is 127.0.0.1 for the
// router's sockets (and back).
var (
	testFar = netip.MustParseAddr("203.0.113.1")
	lo      = netip.MustParseAddr("127.0.0.1")
)

func swapTest(a netip.AddrPort) netip.AddrPort {
	switch a.Addr() {
	case testFar:
		return netip.AddrPortFrom(lo, a.Port())
	case lo:
		return netip.AddrPortFrom(testFar, a.Port())
	}
	return a
}

func far(a netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(testFar.As4()), Port: a.Port()}
}

// rig: a computer (a gVisor stack at 10.66.67.2), the router, and a
// WireGuard stand-in that records what reaches the VPN.
type rig struct {
	ft  *fakeTun
	r   *Router
	pc  *stack.Stack
	vpn chan []byte
}

func newRig(t *testing.T, rules Rules, tweak ...func(*Options)) *rig {
	t.Helper()
	g := &rig{ft: newFakeTun(), vpn: make(chan []byte, 1024)}
	opts := Options{Owner: fakeOwner{`C:\Games\X\game.exe`}, AlwaysVPN: []netip.Prefix{netip.MustParsePrefix("10.66.67.0/24")}, Logf: t.Logf, remap: swapTest}
	for _, f := range tweak {
		f(&opts)
	}
	g.r = New(g.ft, opts, rules)
	g.pc = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(1024, 1280, "")
	g.pc.CreateNIC(1, ep)
	g.pc.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4(me.As4()).WithPrefix()}, stack.AddressProperties{})
	g.pc.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	// The computer's packets enter the adapter...
	go func() {
		for {
			pb := ep.ReadContext(ctx)
			if pb == nil {
				return
			}
			v := pb.ToView()
			pb.DecRef()
			g.ft.out <- append([]byte(nil), v.AsSlice()...)
			v.Release()
		}
	}()
	// ...and the adapter's come back to it.
	go func() {
		for {
			select {
			case b := <-g.ft.in:
				pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
				ep.InjectInbound(ipv4.ProtocolNumber, pb)
				pb.DecRef()
			case <-ctx.Done():
				return
			}
		}
	}()
	// WireGuard reads.
	go func() {
		bufs, sizes := [][]byte{make([]byte, 2000)}, []int{0}
		for {
			n, err := g.r.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			for i := 0; i < n; i++ {
				g.vpn <- append([]byte(nil), bufs[i][:sizes[i]]...)
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		g.r.Close()
		g.pc.Close()
	})
	return g
}

var direct = Rules{On: true, Default: VPN, Apps: []AppRule{{Path: `C:\Games\X`, Folder: true, Route: Direct}}}

func echoTCP(t *testing.T) netip.AddrPort {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return l.Addr().(*net.TCPAddr).AddrPort()
}

func TestDirectTCP(t *testing.T) {
	g := newRig(t, direct)
	addr := echoTCP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, g.pc, far(addr), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg := bytes.Repeat([]byte("split tunneling "), 20000) // 320 KB, many segments
	go c.Write(msg)
	got := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if n, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Logf("got %d of %d", n, len(msg))
		t.Fatalf("echo: %v", err)
	}
	if n := len(g.vpn); n != 0 {
		t.Fatalf("%d packets went to the VPN", n)
	}
	conns := g.r.Conns(10)
	if len(conns) != 1 || conns[0].Route != Direct || conns[0].Name != "game.exe" || conns[0].Down < uint64(len(msg)) {
		t.Fatalf("conns %+v", conns)
	}
}

func TestDirectTCPRefused(t *testing.T) {
	g := newRig(t, direct)
	l, _ := net.Listen("tcp4", "127.0.0.1:0")
	addr := l.Addr().(*net.TCPAddr).AddrPort()
	l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	_, err := gonet.DialContextTCP(ctx, g.pc, far(addr), ipv4.ProtocolNumber)
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("dial to a closed port: %v after %s", err, time.Since(start))
	}
}

func TestVPNPassesUntouched(t *testing.T) {
	rules := direct
	rules.Apps = []AppRule{{Path: `C:\Other\x.exe`, Route: Direct}}
	g := newRig(t, rules)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go gonet.DialContextTCP(ctx, g.pc, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{93, 184, 216, 34}), Port: 443}, ipv4.ProtocolNumber)
	select {
	case b := <-g.vpn:
		var p pkt
		if !parse(b, &p) || !p.syn || p.key.dst.String() != "93.184.216.34:443" {
			t.Fatalf("to the VPN: %x", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nothing reached the VPN")
	}
}

func TestDirectUDP(t *testing.T) {
	g := newRig(t, direct)
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := srv.LocalAddr().(*net.UDPAddr).AddrPort()
	go func() {
		buf := make([]byte, maxDatagram)
		for {
			n, from, err := srv.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			srv.WriteToUDPAddrPort(append([]byte("re:"), buf[:n]...), from)
		}
	}()
	fa := far(addr)
	c, err := gonet.DialUDP(g.pc, nil, &fa, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, maxDatagram)
	for _, size := range []int{5, 1200, 5000} { // 5000: fragments both ways
		msg := bytes.Repeat([]byte{byte(size)}, size)
		if _, err := c.Write(msg); err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := c.Read(buf)
		if err != nil || !bytes.Equal(buf[:n], append([]byte("re:"), msg...)) {
			t.Fatalf("%d bytes: got %d, %v", size, n, err)
		}
	}
	if n := len(g.vpn); n != 0 {
		t.Fatalf("%d packets went to the VPN", n)
	}
}
