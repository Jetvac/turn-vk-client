package main

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// The proxy's TCP connections run in gVisor's TCP stack, inside this
// process. Its defaults suit a LAN: Reno congestion control, which halves
// the send rate on every loss and grows it back by one packet per round
// trip, and 1 MB buffers. Over VK TURN (60–100 ms, routes policed by VK,
// some loss) that kept uploads at 2–8 Mbit/s. Measured on a server, 16
// routes: gVisor's defaults 4–8 Mbit/s, cubic or Reno with 1 MB buffers
// 11–12, cubic with 4 MB buffers 17. The buffers matter most: a sender may
// have only a buffer's worth of data in flight, and 1 MB in flight over
// 100 ms is 80 Mbit/s only without loss; with VK's bursts of loss most of
// it waits for retransmission.
//
// tcpTuning holds the settings; TURNVK_TCP overrides them for experiments:
// "cc=reno,buf=1M,mod=0".
type tcpTuning struct {
	cc  string // congestion control: cubic or reno
	buf int    // default (starting) send and receive buffer, bytes
	max int    // largest buffer auto-tuning may reach, bytes
	mod bool   // receive buffer auto-tuning
}

var defaultTCP = tcpTuning{cc: "cubic", buf: 4 << 20, max: 16 << 20, mod: true}

func parseTCPTuning(s string) (tcpTuning, error) {
	t := defaultTCP
	if s == "off" { // gVisor's own defaults, for comparison
		return t, nil
	}
	for _, kv := range strings.Split(s, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return t, fmt.Errorf("TURNVK_TCP: %q is not key=value", kv)
		}
		var err error
		switch k {
		case "cc":
			t.cc = v
		case "buf":
			t.buf, err = parseSize(v)
		case "max":
			t.max, err = parseSize(v)
		case "mod":
			t.mod = v == "1" || v == "true"
		default:
			err = fmt.Errorf("unknown key %q", k)
		}
		if err != nil {
			return t, fmt.Errorf("TURNVK_TCP: %v", err)
		}
	}
	t.max = max(t.max, t.buf)
	return t, nil
}

func parseSize(v string) (int, error) {
	mul := 1
	switch {
	case strings.HasSuffix(v, "K"):
		mul, v = 1<<10, strings.TrimSuffix(v, "K")
	case strings.HasSuffix(v, "M"):
		mul, v = 1<<20, strings.TrimSuffix(v, "M")
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("bad size %q", v)
	}
	return n * mul, nil
}

func (t tcpTuning) String() string {
	return fmt.Sprintf("cc=%s buf=%dK max=%dK mod=%v", t.cc, t.buf>>10, t.max>>10, t.mod)
}

// netStack returns the gVisor stack behind a netstack.Net. The wireguard
// package keeps it unexported; a test fails if the field moves.
func netStack(n *netstack.Net) (*stack.Stack, error) {
	f := reflect.ValueOf(n).Elem().FieldByName("stack")
	if !f.IsValid() || f.Type() != reflect.TypeOf((*stack.Stack)(nil)) || !f.CanAddr() {
		return nil, fmt.Errorf("netstack layout changed: no stack field")
	}
	return *(**stack.Stack)(unsafe.Pointer(f.UnsafeAddr())), nil
}

func tuneTCP(n *netstack.Net, t tcpTuning) error {
	st, err := netStack(n)
	if err != nil {
		return err
	}
	set := func(name string, opt tcpip.SettableTransportProtocolOption) error {
		if e := st.SetTransportProtocolOption(tcp.ProtocolNumber, opt); e != nil {
			return fmt.Errorf("%s: %v", name, e)
		}
		return nil
	}
	cc := tcpip.CongestionControlOption(t.cc)
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: t.buf, Max: t.max}
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: t.buf, Max: t.max}
	mod := tcpip.TCPModerateReceiveBufferOption(t.mod)
	for _, o := range []struct {
		name string
		opt  tcpip.SettableTransportProtocolOption
	}{{"congestion control", &cc}, {"send buffer", &snd}, {"receive buffer", &rcv}, {"buffer tuning", &mod}} {
		if err := set(o.name, o.opt); err != nil {
			return err
		}
	}
	// The stack-wide socket limits cap the per-socket ones.
	sb := tcpip.SendBufferSizeOption{Min: 4 << 10, Default: t.buf, Max: t.max}
	rb := tcpip.ReceiveBufferSizeOption{Min: 4 << 10, Default: t.buf, Max: t.max}
	if e := st.SetOption(sb); e != nil {
		return fmt.Errorf("stack send buffer: %v", e)
	}
	if e := st.SetOption(rb); e != nil {
		return fmt.Errorf("stack receive buffer: %v", e)
	}
	return nil
}
