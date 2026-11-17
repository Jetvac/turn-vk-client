package split

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// Large UDP datagrams (some games, DNS with DNSSEC) leave the computer in
// IPv4 fragments; only the first carries the ports. For direct flows the
// fragments are put back together and the datagram goes out whole; for the
// VPN they pass as they are.

type fragKey struct {
	src, dst netip.Addr
	id       uint16
}

type fragState struct {
	f     *flow
	start time.Time
	data  []byte // the UDP header and payload so far
	have  int    // bytes received
}

const maxDatagram = 65535

func fragOf(b []byte, p *pkt) (fragKey, int, bool) {
	k := fragKey{p.key.src.Addr(), p.key.dst.Addr(), binary.BigEndian.Uint16(b[4:6])}
	ff := binary.BigEndian.Uint16(b[6:8])
	return k, int(ff&0x1fff) * 8, ff&0x2000 != 0
}

// startFragments keeps the first fragment of a direct datagram.
func (r *Router) startFragments(b []byte, p *pkt, f *flow) {
	k, _, _ := fragOf(b, p)
	total := int(binary.BigEndian.Uint16(b[2:4]))
	s := &fragState{f: f, start: time.Now(), data: make([]byte, 0, 2*(total-p.ihl))}
	s.data = append(s.data, b[p.ihl:total]...)
	s.have = len(s.data)
	r.mu.Lock()
	if len(r.frags) < 256 {
		r.frags[k] = s
	}
	r.mu.Unlock()
}

// fragment takes a later fragment; true when it belongs to a direct
// datagram (and is consumed).
func (r *Router) fragment(b []byte, p *pkt) bool {
	k, off, more := fragOf(b, p)
	r.mu.Lock()
	s := r.frags[k]
	r.mu.Unlock()
	if s == nil {
		return false
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	data := b[p.ihl:total]
	if off+len(data) > maxDatagram {
		r.dropFrag(k)
		return true
	}
	if need := off + len(data); need > len(s.data) {
		s.data = append(s.data, make([]byte, need-len(s.data))...)
	}
	copy(s.data[off:], data)
	s.have += len(data)
	s.f.up.Add(uint64(len(b)))
	if more || s.have < len(s.data) {
		return true
	}
	r.dropFrag(k)
	if len(s.data) >= 8 {
		ul := int(binary.BigEndian.Uint16(s.data[4:6]))
		if ul >= 8 && ul <= len(s.data) {
			r.udp.send(s.f, s.data[8:ul])
		}
	}
	return true
}

func (r *Router) dropFrag(k fragKey) {
	r.mu.Lock()
	delete(r.frags, k)
	r.mu.Unlock()
}
