//go:build windows

package winvpn

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

// debugTun logs the first packets each way between Windows and WireGuard,
// for finding where traffic stops ("--debug-run").
type debugTun struct {
	tun.Device
	logf      func(string, ...any)
	out, in   atomic.Int64 // packets
	outB, inB atomic.Int64
}

const debugPackets = 40

// Debug wraps the adapter so that its packets are logged.
func Debug(d tun.Device, logf func(string, ...any)) tun.Device {
	return &debugTun{Device: d, logf: logf}
}

// Read: packets programs sent (Windows -> tunnel).
func (t *debugTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(bufs, sizes, offset)
	for i := 0; i < n; i++ {
		c := t.out.Add(1)
		t.outB.Add(int64(sizes[i]))
		if c <= debugPackets {
			t.logf("debug: Windows -> tunnel #%d %s", c, describe(bufs[i][offset:offset+sizes[i]]))
		}
	}
	return n, err
}

// Write: packets from the server (tunnel -> Windows).
func (t *debugTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		c := t.in.Add(1)
		t.inB.Add(int64(len(b) - offset))
		if c <= debugPackets {
			t.logf("debug: tunnel -> Windows #%d %s", c, describe(b[offset:]))
		}
	}
	n, err := t.Device.Write(bufs, offset)
	if err != nil {
		t.logf("debug: writing to the adapter: %d of %d written: %v", n, len(bufs), err)
	}
	return n, err
}

// Counts returns the packets and bytes each way.
func (t *debugTun) Counts() string {
	return fmt.Sprintf("Windows -> tunnel %d packets (%d B), tunnel -> Windows %d packets (%d B)", t.out.Load(), t.outB.Load(), t.in.Load(), t.inB.Load())
}

// DebugCounts returns a debug adapter's counters ("" for another device).
func DebugCounts(d tun.Device) string {
	if t, ok := d.(*debugTun); ok {
		return t.Counts()
	}
	return ""
}

// describe summarizes an IP packet: protocol, addresses, ports, length,
// and whether the IPv4 header checksum is right.
func describe(p []byte) string {
	if len(p) < 20 {
		return fmt.Sprintf("%d B (too short)", len(p))
	}
	switch p[0] >> 4 {
	case 4:
		ihl := int(p[0]&15) * 4
		if ihl < 20 || len(p) < ihl {
			return fmt.Sprintf("IPv4 bad header length %d", ihl)
		}
		src, _ := netip.AddrFromSlice(p[12:16])
		dst, _ := netip.AddrFromSlice(p[16:20])
		total := int(binary.BigEndian.Uint16(p[2:4]))
		proto := p[9]
		ports := ""
		if (proto == 6 || proto == 17) && len(p) >= ihl+4 {
			ports = fmt.Sprintf(" %d->%d", binary.BigEndian.Uint16(p[ihl:]), binary.BigEndian.Uint16(p[ihl+2:]))
		}
		flags := ""
		if proto == 6 && len(p) >= ihl+14 {
			f := p[ihl+13]
			for i, name := range []string{"FIN", "SYN", "RST", "PSH", "ACK"} {
				if f&(1<<i) != 0 {
					flags += " " + name
				}
			}
		}
		ck := "ok"
		if !ipv4ChecksumOK(p[:ihl]) {
			ck = "BAD"
		}
		name := map[byte]string{1: "ICMP", 6: "TCP", 17: "UDP"}[proto]
		if name == "" {
			name = fmt.Sprintf("proto %d", proto)
		}
		return fmt.Sprintf("IPv4 %s %s -> %s%s%s, %d B (header says %d), ttl %d, header checksum %s", name, src, dst, ports, flags, len(p), total, p[8], ck)
	case 6:
		src, _ := netip.AddrFromSlice(p[8:24])
		dst, _ := netip.AddrFromSlice(p[24:40])
		return fmt.Sprintf("IPv6 next %d %s -> %s, %d B", p[6], src, dst, len(p))
	}
	return fmt.Sprintf("version %d, %d B", p[0]>>4, len(p))
}

func ipv4ChecksumOK(h []byte) bool {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum) == 0xffff
}
