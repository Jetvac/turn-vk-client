package split

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// portOwner names the program by the local port.
type portOwner map[uint16]string

func (o portOwner) Lookup(_ uint8, local, _ netip.AddrPort, _ bool) *Proc {
	return &Proc{PID: uint32(local.Port()), Path: o[local.Port()]}
}

// An anti-cheat service goes where the game that ran last goes.
func TestAntiCheatFollowsGame(t *testing.T) {
	defer func(f func() []string) { antiCheatDirs = f }(antiCheatDirs)
	antiCheatDirs = func() []string { return []string{normPath(`C:\Program Files (x86)\EasyAntiCheat_EOS`)} }
	own := portOwner{1: `C:\Games\X\game.exe`, 2: `C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.exe`}
	r := New(newFakeTun(), Options{Owner: own, Logf: t.Logf}, direct)
	defer r.Close()
	m := r.m.Load()
	flow := func(port uint16, dst string) *flow {
		var p pkt
		src := netip.AddrPortFrom(me, port)
		if !parse(udpPackets(src, netip.MustParseAddrPort(dst), []byte("hi"), 1280, 0, 1)[0], &p) {
			t.Fatal("parse")
		}
		return r.newFlow(&p, m, time.Now().UnixNano())
	}
	if f := flow(2, "198.51.100.1:443"); f.route != VPN {
		t.Fatalf("no game yet: anti-cheat %v (%s)", f.route, f.why)
	}
	if f := flow(1, "203.0.113.1:7777"); f.route != Direct {
		t.Fatalf("game %v", f.route)
	}
	if f := flow(2, "198.51.100.2:9000"); f.route != Direct || !strings.Contains(f.why, "game.exe") {
		t.Fatalf("anti-cheat with the game direct: %v (%s)", f.route, f.why)
	}
	r.appFail(`C:\Games\X\game.exe`, "test")
	if f := flow(2, "198.51.100.3:9000"); f.route != VPN {
		t.Fatalf("anti-cheat with the game moved to the VPN: %v (%s)", f.route, f.why)
	}
}
