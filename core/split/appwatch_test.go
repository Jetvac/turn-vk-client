package split

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// A game whose direct UDP gets no answer goes through the VPN, all of it;
// one that is answered stays direct.
func TestAppWatch(t *testing.T) {
	defer func(n int32, w time.Duration) { appProbeMin, appProbeWait = n, w }(appProbeMin, appProbeWait)
	appProbeMin, appProbeWait = 3, 50*time.Millisecond
	const game = `C:\Games\X\game.exe`
	r := New(newFakeTun(), Options{Owner: fakeOwner{game}, Logf: t.Logf, remap: swapTest}, direct)
	defer r.Close()
	m := r.m.Load()
	flowTo := func(src, dst netip.AddrPort) *flow {
		var p pkt
		if !parse(udpPackets(src, dst, []byte("hi"), 1280, 0, 1)[0], &p) {
			t.Fatal("parse")
		}
		return r.newFlow(&p, m, time.Now().UnixNano())
	}

	// Answered: an echo on 127.0.0.1 (203.0.113.1 to the router).
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			echo.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	echoAt := netip.AddrPortFrom(testFar, uint16(echo.LocalAddr().(*net.UDPAddr).Port))
	f := flowTo(netip.MustParseAddrPort("10.66.67.2:50000"), echoAt)
	if !f.byApp || f.probe == nil {
		t.Fatal("the game is not watched")
	}
	for i := 0; i < 10; i++ {
		r.udp.send(f, []byte("ping"))
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if r.appFailed(game) || !f.probe.ok.Load() {
		t.Fatal("an answered game was moved")
	}

	// Not answered: a port nobody listens on, for a game watched afresh.
	r.amu.Lock()
	r.probes = nil
	r.amu.Unlock()
	dead, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	deadAt := netip.AddrPortFrom(testFar, uint16(dead.LocalAddr().(*net.UDPAddr).Port))
	dead.Close()
	g := flowTo(netip.MustParseAddrPort("10.66.67.2:50001"), deadAt)
	for i := 0; i < 10; i++ {
		r.udp.send(g, []byte("ping"))
		time.Sleep(10 * time.Millisecond)
	}
	for end := time.Now().Add(time.Second); !r.appFailed(game) && time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
	}
	if !r.appFailed(game) {
		t.Fatal("an unanswered game stayed direct")
	}
	time.Sleep(20 * time.Millisecond)
	if g.local.Load() || g.route != VPN {
		t.Fatal("its flow was not moved")
	}
	if h := flowTo(netip.MustParseAddrPort("10.66.67.2:50002"), echoAt); h.route != VPN || h.why != whyAppFailed {
		t.Fatalf("a new flow of it: %v (%s)", h.route, h.why)
	}
	if fs := r.Failures(); len(fs) == 0 || fs[0].Addr != "game.exe" {
		t.Fatalf("not listed: %+v", fs)
	}
	r.ForgetFailures()
	if r.appFailed(game) {
		t.Fatal("forgetting the failures kept it")
	}
}

// A connection that fails direct moves a game still waiting for its first
// UDP answer, not one whose UDP works.
func TestAppWatchTCP(t *testing.T) {
	const game = `C:\Games\X\game.exe`
	r := New(newFakeTun(), Options{Logf: t.Logf}, direct)
	defer r.Close()
	now := time.Now().UnixNano()
	f := &flow{key: flowKey{protoTCP, netip.MustParseAddrPort("10.66.67.2:50000"), netip.MustParseAddrPort("203.0.113.1:443")}, byApp: true, path: game}
	p := r.probeFor(game, now)
	p.ok.Store(true)
	r.noteFailed(f, "login.example.com", errClosed, true)
	time.Sleep(20 * time.Millisecond)
	if r.appFailed(game) {
		t.Fatal("a game in play was moved")
	}
	p.ok.Store(false)
	r.noteFailed(f, "login.example.com", errClosed, true)
	for end := time.Now().Add(time.Second); !r.appFailed(game) && time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
	}
	if !r.appFailed(game) {
		t.Fatal("a starting game stayed direct")
	}
}
