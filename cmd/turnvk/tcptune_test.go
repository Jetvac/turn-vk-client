package main

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestTuneTCP(t *testing.T) {
	_, n, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	if err := tuneTCP(n, defaultTCP); err != nil {
		t.Fatal(err)
	}
	st, _ := netStack(n)
	var cc tcpip.CongestionControlOption
	if e := st.TransportProtocolOption(tcp.ProtocolNumber, &cc); e != nil || string(cc) != "cubic" {
		t.Fatalf("congestion control %q, %v", cc, e)
	}
	var snd tcpip.TCPSendBufferSizeRangeOption
	if e := st.TransportProtocolOption(tcp.ProtocolNumber, &snd); e != nil || snd.Max != defaultTCP.max {
		t.Fatalf("send buffer %+v, %v", snd, e)
	}
}

func TestParseTCPTuning(t *testing.T) {
	got, err := parseTCPTuning("cc=reno, buf=512K,mod=0")
	if err != nil {
		t.Fatal(err)
	}
	want := tcpTuning{cc: "reno", buf: 512 << 10, max: defaultTCP.max, mod: false}
	if got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
	if _, err := parseTCPTuning("buf=x"); err == nil {
		t.Fatal("bad size accepted")
	}
}
