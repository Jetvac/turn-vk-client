package engine

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v4"

	"github.com/Jetvac/turn-vk-client/core/netx"
	"github.com/Jetvac/turn-vk-client/core/session"
)

func netEngine(t *testing.T, routes int) (*Engine, []*session.Session) {
	e := &Engine{b: newBind(), state: StateConnected}
	e.ctx, e.stop = context.WithCancel(context.Background())
	t.Cleanup(e.stop)
	e.mode.Store(modeDirect)
	list := testRoutes(routes)
	for _, s := range list {
		e.b.add(s)
	}
	return e, list
}

// Half the routes failing to send for lack of network is an outage; one
// relay out of reach is not.
func TestNetDown(t *testing.T) {
	e, list := netEngine(t, 4)
	now := time.Now()
	list[0].NetErrAt.Store(now.UnixNano())
	if e.netDown(now) {
		t.Fatal("one route's error taken for an outage")
	}
	list[1].NetErrAt.Store(now.UnixNano())
	if !e.netDown(now) {
		t.Fatal("half the routes failing is no outage")
	}
	if e.netDown(now.Add(netHold + time.Second)) {
		t.Fatal("old errors still count")
	}
	// The platform's reports (no routes here: NetworkBack probes them).
	e, _ = netEngine(t, 0)
	e.NetworkLost()
	if !e.netDown(now.Add(time.Hour)) {
		t.Fatal("the platform's report ignored")
	}
	e.NetworkBack()
	if e.netDown(now.Add(time.Hour)) {
		t.Fatal("still down after the network came back")
	}
}

// Without network, routes that do not answer are kept, not closed.
func TestNoNetworkKeepsRoutes(t *testing.T) {
	e, list := netEngine(t, 4)
	for _, s := range list {
		s.LastRx.Store(time.Now().Add(-time.Minute).UnixNano()) // silent
	}
	e.NetworkLost()
	e.probing.Store(true)
	e.replaceDeadPaths("test", e.b.rx.Load(), list)
	for _, s := range list {
		if s.Closed() {
			t.Fatal("a route closed without network")
		}
	}
	if e.probing.Load() {
		t.Fatal("probing flag left set")
	}
}

// A network switch closes half the routes at once and the rest once a new
// route answers.
func TestSwitchNetwork(t *testing.T) {
	e, list := netEngine(t, 4)
	e.SwitchNetwork("test")
	closed := 0
	for _, s := range list {
		if s.Closed() {
			closed++
		}
	}
	if closed != 2 {
		t.Fatalf("%d of 4 closed at once, want 2", closed)
	}
	time.Sleep(300 * time.Millisecond)
	if list[1].Closed() || list[3].Closed() {
		t.Fatal("old routes closed before a new one answered")
	}
	n := session.NewTestSession("t") // opened on the new network
	e.b.add(n)
	deadline := time.Now().Add(2 * time.Second)
	for !(list[1].Closed() && list[3].Closed()) {
		if time.Now().After(deadline) {
			t.Fatal("old routes kept after a new one answered")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n.Closed() {
		t.Fatal("the new route closed")
	}
}

// A relay probe measures a STUN server's round trip.
func TestStunRTT(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var m stun.Message
			m.Raw = append(m.Raw[:0], buf[:n]...)
			if m.Decode() != nil {
				continue
			}
			res := stun.MustBuild(stun.NewTransactionIDSetter(m.TransactionID), stun.BindingSuccess,
				&stun.XORMappedAddress{IP: from.IP, Port: from.Port}, stun.Fingerprint)
			time.Sleep(20 * time.Millisecond)
			_, _ = c.WriteToUDP(res.Raw, from)
		}
	}()
	d, err := stunRTT(context.Background(), &netx.Net{}, c.LocalAddr().String())
	if err != nil || d < 20*time.Millisecond || d > time.Second {
		t.Fatalf("rtt %v, %v", d, err)
	}
	// Nothing answers: an error, within the tries.
	q, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer q.Close()
	start := time.Now()
	if _, err := stunRTT(context.Background(), &netx.Net{}, q.LocalAddr().String()); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("silent server: %v after %v", err, time.Since(start))
	}
}
