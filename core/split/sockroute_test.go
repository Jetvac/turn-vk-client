package split

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// seqOwner names the game for its first lookup and another program after
// (Windows gave the port to it, as an old table would say).
type seqOwner struct{ n atomic.Int32 }

func (o *seqOwner) Lookup(uint8, netip.AddrPort, netip.AddrPort, bool) *Proc {
	if o.n.Add(1) == 1 {
		return &Proc{PID: 42, Path: `C:\Games\X\game.exe`}
	}
	return &Proc{PID: 43, Path: `C:\Apps\other.exe`}
}

// All destinations of a game's UDP socket take the route its rule gave
// the first: one address for the matchmaking and the match.
func TestSockRoute(t *testing.T) {
	own := &seqOwner{}
	r := New(newFakeTun(), Options{Owner: own, Logf: t.Logf}, direct)
	defer r.Close()
	m := r.m.Load()
	src := netip.MustParseAddrPort("10.66.67.2:50000")
	now := time.Now().UnixNano()
	mk := func(dst string) *pkt {
		var p pkt
		b := udpPackets(src, netip.MustParseAddrPort(dst), []byte("hi"), 1280, 0, 1)[0]
		if !parse(b, &p) {
			t.Fatal("parse")
		}
		return &p
	}
	for i, dst := range []string{"203.0.113.1:7777", "198.51.100.9:22222", "192.0.2.5:9000"} {
		f := r.newFlow(mk(dst), m, now)
		if f.route != Direct || f.pid != 42 {
			t.Fatalf("destination %d: %v (%s), pid %d", i, f.route, f.why, f.pid)
		}
	}
	if n := own.n.Load(); n != 1 {
		t.Fatalf("%d lookups for one socket", n)
	}
	// Another socket is looked up; new rules forget the sockets.
	other := netip.MustParseAddrPort("10.66.67.2:50001")
	var p pkt
	parse(udpPackets(other, netip.MustParseAddrPort("203.0.113.1:7777"), []byte("hi"), 1280, 0, 1)[0], &p)
	if f := r.newFlow(&p, m, now); f.route != VPN || f.pid != 43 {
		t.Fatalf("other socket: %v, pid %d", f.route, f.pid)
	}
	r.SetRules(direct)
	if f := r.newFlow(mk("203.0.113.1:7778"), r.m.Load(), now); f.pid != 43 {
		t.Fatalf("socket kept across new rules: pid %d", f.pid)
	}
}

// Past maxNATSocks direct UDP sockets, the one used longest ago closes;
// failed sends are counted.
func TestNATSockCap(t *testing.T) {
	defer func(n int) { maxNATSocks = n }(maxNATSocks)
	maxNATSocks = 3
	r := New(newFakeTun(), Options{Logf: t.Logf}, Rules{})
	defer r.Close()
	u := r.udp
	var first *natSock
	for i := 0; i < 4; i++ {
		s := u.sock(netip.AddrPortFrom(me, uint16(40000+i)))
		if s == nil {
			t.Fatal("no socket")
		}
		s.last.Store(int64(i + 1))
		if i == 0 {
			first = s
		}
	}
	if n := u.count(); n != 3 {
		t.Fatalf("%d sockets", n)
	}
	if _, err := first.c.WriteToUDPAddrPort([]byte("x"), netip.MustParseAddrPort("127.0.0.1:9")); err == nil {
		t.Fatal("the oldest socket is still open")
	}
	u.noteSendErr(nil)
	u.noteSendErr(errClosed)
	if st := r.Stats(); st.UDPSocks != 3 || st.UDPErr != 1 {
		t.Fatalf("%+v", st)
	}
}

var errClosed = errors.New("closed")

// Direct IPv6 without an IPv6 network, and IPv6 meant for the VPN, are
// answered "unreachable" at once.
func TestUnreachable6(t *testing.T) {
	ft := newFakeTun()
	r := New(ft, Options{Logf: t.Logf}, Rules{})
	defer r.Close()
	r.udp.no6.Store(time.Now().Add(time.Minute).UnixNano())
	src := netip.AddrPortFrom(me6, 50000)
	dst := netip.MustParseAddrPort("[2001:db8::7]:7777")
	f := &flow{key: flowKey{protoUDP, src, dst}}
	r.udp.send(f, []byte("hello"))
	var b []byte
	select {
	case b = <-ft.in:
	case <-time.After(time.Second):
		t.Fatal("no answer")
	}
	if b[0]>>4 != 6 || b[6] != 58 || b[40] != 1 || b[41] != 0 {
		t.Fatalf("not ICMPv6 unreachable: % x", b[:48])
	}
	if netip.AddrFrom16([16]byte(b[8:24])) != dst.Addr() || netip.AddrFrom16([16]byte(b[24:40])) != src.Addr() {
		t.Fatal("addresses")
	}
	var ps uint32
	for i := 8; i < 40; i += 2 {
		ps += uint32(b[i])<<8 | uint32(b[i+1])
	}
	ps += 58 + uint32(len(b)-40)
	if checksum(b[40:], ps) != 0 {
		t.Fatal("bad checksum")
	}
	if inv := b[48:]; len(inv) != 40+8+5 || string(inv[48:]) != "hello" {
		t.Fatalf("invoking packet %d bytes", len(inv))
	}
	if n := r.udp.count(); n != 0 {
		t.Fatalf("%d sockets tried", n)
	}
}
