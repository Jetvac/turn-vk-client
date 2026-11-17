//go:build windows

package split

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
)

// The lookup finds this test's own sockets (loopback only, nothing leaves
// the computer).
func TestOwnerFindsOwnSockets(t *testing.T) {
	exe, _ := os.Executable()
	o := NewOwner()

	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	p := o.Lookup(protoUDP, u.LocalAddr().(*net.UDPAddr).AddrPort(), u.LocalAddr().(*net.UDPAddr).AddrPort(), true)
	if p == nil || p.PID != uint32(os.Getpid()) || !strings.EqualFold(p.Path, exe) {
		t.Fatalf("UDP: %+v, want pid %d %s", p, os.Getpid(), exe)
	}
	if len(p.Parents) == 0 {
		t.Fatal("no parents (go test started this process)")
	}

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	local := c.LocalAddr().(*net.TCPAddr).AddrPort()
	remote := c.RemoteAddr().(*net.TCPAddr).AddrPort()
	if p := o.Lookup(protoTCP, local, remote, false); p == nil || p.PID != uint32(os.Getpid()) {
		t.Fatalf("TCP: %+v", p)
	}
	// A socket that does not exist.
	if p := o.Lookup(protoTCP, local, netip.AddrPortFrom(remote.Addr(), 1), false); p != nil {
		t.Fatalf("unknown socket: %+v", p)
	}
}
