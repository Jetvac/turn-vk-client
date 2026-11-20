package split

import (
	"encoding/binary"
	"net/netip"
)

const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17
)

// flowKey identifies a connection from the computer's side.
type flowKey struct {
	proto uint8
	src   netip.AddrPort // the program's end
	dst   netip.AddrPort
}

// pkt is what the router needs of an IP packet.
type pkt struct {
	key      flowKey
	v6       bool
	ihl      int  // header length
	frag     bool // a fragment (more fragments, or not the first)
	firstFrg bool // the first fragment of several
	syn      bool // TCP SYN without ACK: a new connection
	fin, rst bool
	payload  []byte // the transport payload (UDP), when not a fragment
}

// parse reads an IPv4 or IPv6 TCP or UDP packet; ok is false for anything
// else (ICMP, IPv6 extension headers, broken packets), which the router
// leaves to the VPN.
func parse(b []byte, p *pkt) bool {
	if len(b) >= 40 && b[0]>>4 == 6 {
		return parse6(b, p)
	}
	if len(b) < 20 || b[0]>>4 != 4 {
		return false
	}
	ihl := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if ihl < 20 || total < ihl || total > len(b) {
		return false
	}
	b = b[:total]
	proto := b[9]
	if proto != protoTCP && proto != protoUDP {
		return false
	}
	ff := binary.BigEndian.Uint16(b[6:8])
	more, off := ff&0x2000 != 0, ff&0x1fff
	*p = pkt{ihl: ihl, frag: more || off != 0, firstFrg: more && off == 0}
	src := netip.AddrFrom4([4]byte(b[12:16]))
	dst := netip.AddrFrom4([4]byte(b[16:20]))
	if off != 0 {
		// No ports in later fragments.
		p.key = flowKey{proto: proto, src: netip.AddrPortFrom(src, 0), dst: netip.AddrPortFrom(dst, 0)}
		return true
	}
	t := b[ihl:]
	if len(t) < 8 {
		return false
	}
	return transport(p, proto, src, dst, t)
}

// parse6: an IPv6 packet whose next header is TCP or UDP (extension
// headers and fragments are left to the VPN, which drops them).
func parse6(b []byte, p *pkt) bool {
	plen := int(binary.BigEndian.Uint16(b[4:6]))
	if 40+plen > len(b) {
		return false
	}
	b = b[:40+plen]
	proto := b[6]
	if proto != protoTCP && proto != protoUDP {
		return false
	}
	*p = pkt{v6: true, ihl: 40}
	src := netip.AddrFrom16([16]byte(b[8:24]))
	dst := netip.AddrFrom16([16]byte(b[24:40]))
	t := b[40:]
	if len(t) < 8 {
		return false
	}
	return transport(p, proto, src, dst, t)
}

// transport reads the ports and flags.
func transport(p *pkt, proto uint8, src, dst netip.Addr, t []byte) bool {
	sp, dp := binary.BigEndian.Uint16(t[0:2]), binary.BigEndian.Uint16(t[2:4])
	p.key = flowKey{proto: proto, src: netip.AddrPortFrom(src, sp), dst: netip.AddrPortFrom(dst, dp)}
	switch proto {
	case protoTCP:
		if len(t) < 14 {
			return false
		}
		fl := t[13]
		p.syn = fl&0x02 != 0 && fl&0x10 == 0
		p.fin = fl&0x01 != 0
		p.rst = fl&0x04 != 0
	case protoUDP:
		if !p.frag {
			ul := int(binary.BigEndian.Uint16(t[4:6]))
			if ul < 8 || ul > len(t) {
				return false
			}
			p.payload = t[8:ul]
		}
	}
	return true
}

// icmp6Unreachable builds the ICMPv6 "destination unreachable, no route"
// a router would send back for the IPv6 packet inv (as much of it as
// fits in IPv6's minimum MTU), from dst to src.
func icmp6Unreachable(src, dst netip.Addr, inv []byte) []byte {
	if max := 1280 - 40 - 8; len(inv) > max {
		inv = inv[:max]
	}
	b := make([]byte, 40+8+len(inv))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(8+len(inv)))
	b[6] = 58 // ICMPv6
	b[7] = 64
	s16, d16 := src.As16(), dst.As16()
	copy(b[8:24], s16[:])
	copy(b[24:40], d16[:])
	m := b[40:]
	m[0], m[1] = 1, 0 // destination unreachable: no route
	copy(m[8:], inv)
	var ps uint32
	for i := 0; i < 16; i += 2 {
		ps += uint32(s16[i])<<8 | uint32(s16[i+1])
		ps += uint32(d16[i])<<8 | uint32(d16[i+1])
	}
	ps += 58 + uint32(len(m))
	binary.BigEndian.PutUint16(m[2:], checksum(m, ps))
	return b
}

// checksum is the Internet checksum of b, starting from sum.
func checksum(b []byte, sum uint32) uint16 {
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// udpPackets builds the IPv4 packets carrying a UDP datagram from src to
// dst, split into fragments when it does not fit mtu. Each packet starts at
// offset in its buffer (WireGuard's tun.Device convention).
func udpPackets(src, dst netip.AddrPort, payload []byte, mtu, offset int, id uint16) [][]byte {
	if src.Addr().Is6() {
		return udpPacket6(src, dst, payload, offset)
	}
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], src.Port())
	binary.BigEndian.PutUint16(udp[2:], dst.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)
	s4, d4 := src.Addr().As4(), dst.Addr().As4()
	// Pseudo-header: addresses, protocol, length.
	var ps uint32
	for i := 0; i < 4; i += 2 {
		ps += uint32(s4[i])<<8 | uint32(s4[i+1])
		ps += uint32(d4[i])<<8 | uint32(d4[i+1])
	}
	ps += protoUDP + uint32(len(udp))
	cs := checksum(udp, ps)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], cs)

	maxData := (mtu - 20) &^ 7
	var out [][]byte
	for off := 0; off < len(udp); off += maxData {
		end := min(off+maxData, len(udp))
		b := make([]byte, offset+20+end-off)
		h := b[offset:]
		h[0] = 0x45
		binary.BigEndian.PutUint16(h[2:], uint16(20+end-off))
		binary.BigEndian.PutUint16(h[4:], id)
		ff := uint16(off / 8)
		if end < len(udp) {
			ff |= 0x2000
		}
		binary.BigEndian.PutUint16(h[6:], ff)
		h[8] = 64
		h[9] = protoUDP
		copy(h[12:16], s4[:])
		copy(h[16:20], d4[:])
		binary.BigEndian.PutUint16(h[10:], checksum(h[:20], 0))
		copy(h[20:], udp[off:end])
		out = append(out, b)
	}
	return out
}

// udpPacket6 builds the IPv6 packet carrying a UDP datagram (IPv6 is not
// fragmented on the way: the program's own path MTU applies).
func udpPacket6(src, dst netip.AddrPort, payload []byte, offset int) [][]byte {
	if 8+len(payload) > 0xffff {
		return nil
	}
	b := make([]byte, offset+40+8+len(payload))
	h := b[offset:]
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(payload)))
	h[6] = protoUDP
	h[7] = 64
	s16, d16 := src.Addr().As16(), dst.Addr().As16()
	copy(h[8:24], s16[:])
	copy(h[24:40], d16[:])
	udp := h[40:]
	binary.BigEndian.PutUint16(udp[0:], src.Port())
	binary.BigEndian.PutUint16(udp[2:], dst.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	copy(udp[8:], payload)
	var ps uint32
	for i := 0; i < 16; i += 2 {
		ps += uint32(s16[i])<<8 | uint32(s16[i+1])
		ps += uint32(d16[i])<<8 | uint32(d16[i+1])
	}
	ps += protoUDP + uint32(len(udp))
	cs := checksum(udp, ps)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], cs)
	return [][]byte{b}
}
