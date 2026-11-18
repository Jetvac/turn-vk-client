package split

// QUIC (HTTP/3) carries the TLS ClientHello in its Initial packets,
// encrypted with keys anyone can derive from the packet's destination
// connection ID (RFC 9001, section 5.2): the protection is against
// tampering, not reading. The router holds a new QUIC flow's first packets
// (at most 300 ms), reads the server name from them, routes the flow and
// sends the held packets on.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	quicWait    = 300 * time.Millisecond
	quicMaxHeld = 12
	quicV1      = 0x00000001
	quicV2      = 0x6b3343cf
)

var (
	quicSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicSaltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

// quicSniff is a QUIC flow waiting for its name.
type quicSniff struct {
	mu     sync.Mutex
	prelim Decision
	held   [][]byte
	chunks []cryptoChunk
	done   bool
	timer  *time.Timer
}

type cryptoChunk struct {
	off  uint64
	data []byte
}

// quicTimer routes the flow without a name if none comes in time.
func (r *Router) quicTimer(f *flow) {
	q := f.quic
	q.timer = time.AfterFunc(quicWait, func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		if !q.done {
			r.quicFinish(f, "")
		}
	})
}

// quicHold takes a packet of a waiting QUIC flow; false once the flow is
// routed (the packet goes the usual way).
func (r *Router) quicHold(f *flow, b []byte, p *pkt) bool {
	q := f.quic
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.done {
		return false
	}
	if p.frag {
		r.quicFinish(f, "")
		return false
	}
	q.held = append(q.held, append([]byte(nil), b...))
	host, ok := q.feed(p.payload)
	if ok || len(q.held) >= quicMaxHeld {
		r.quicFinish(f, host)
	}
	return true
}

// quicFinish routes the flow and sends the held packets; q.mu is held.
func (r *Router) quicFinish(f *flow, host string) {
	q := f.quic
	q.done = true
	if q.timer != nil {
		q.timer.Stop()
	}
	d := r.decideSniffed(f, host, q.prelim)
	if f.qretry && d.Route == Direct && r.failedBeforeQUIC(host, f.key.dst.Addr()) {
		d = Decision{VPN, whyFailed}
		f.viaVPN = true
	}
	r.settle(f, host, d)
	held := q.held
	q.held, q.chunks = nil, nil
	if d.Route == VPN {
		f.local.Store(false)
		for _, b := range held {
			r.injectPkt(b)
		}
		return
	}
	f.local.Store(true)
	if f.qretry {
		r.quicWatch(f)
		for _, b := range held {
			f.quicKeepPkt(b)
		}
	}
	var p pkt
	for _, b := range held {
		if parse(b, &p) && !p.frag {
			r.udp.send(f, p.payload)
		}
	}
}

// feed reads a datagram's Initial packets; ok once the name is found or
// cannot be (not QUIC, another version).
func (q *quicSniff) feed(d []byte) (string, bool) {
	seen := false
	for len(d) > 0 {
		n, frames, isInitial, ok := quicInitial(d)
		if !ok {
			return "", !seen
		}
		seen = true
		if isInitial {
			q.addFrames(frames)
		}
		d = d[n:]
	}
	msg := q.assembled()
	if len(msg) >= 4 && enough(msg) {
		return clientHelloSNI(msg), true
	}
	return "", false
}

func (q *quicSniff) addFrames(p []byte) {
	for len(p) > 0 {
		typ, n := quicVarint(p)
		if n == 0 {
			return
		}
		p = p[n:]
		switch {
		case typ == 0x00 || typ == 0x01: // PADDING, PING
		case typ == 0x02 || typ == 0x03: // ACK
			cnt := 4
			for i := 0; i < cnt && len(p) > 0; i++ {
				v, n := quicVarint(p)
				if n == 0 {
					return
				}
				p = p[n:]
				if i == 2 {
					cnt += 2 * int(v) // gap and range per extra range
				}
			}
			if typ == 0x03 {
				for i := 0; i < 3; i++ {
					_, n := quicVarint(p)
					if n == 0 {
						return
					}
					p = p[n:]
				}
			}
		case typ == 0x06: // CRYPTO
			off, n1 := quicVarint(p)
			if n1 == 0 {
				return
			}
			l, n2 := quicVarint(p[n1:])
			if n2 == 0 || uint64(len(p)-n1-n2) < l {
				return
			}
			data := p[n1+n2 : n1+n2+int(l)]
			if off+l <= 64<<10 {
				q.chunks = append(q.chunks, cryptoChunk{off, append([]byte(nil), data...)})
			}
			p = p[n1+n2+int(l):]
		default:
			return // nothing else is expected before the handshake
		}
	}
}

// assembled returns the CRYPTO data contiguous from offset 0.
func (q *quicSniff) assembled() []byte {
	sort.Slice(q.chunks, func(i, j int) bool { return q.chunks[i].off < q.chunks[j].off })
	var out []byte
	for _, c := range q.chunks {
		end := c.off + uint64(len(c.data))
		if c.off > uint64(len(out)) {
			break
		}
		if end > uint64(len(out)) {
			out = append(out, c.data[uint64(len(out))-c.off:]...)
		}
	}
	return out
}

func quicVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}

// quicInitial reads the long-header packet at the start of d: its length
// (n), and the decrypted frames when it is a client Initial.
func quicInitial(d []byte) (n int, frames []byte, isInitial, ok bool) {
	if len(d) < 7 || d[0]&0x80 == 0 {
		return 0, nil, false, false
	}
	version := binary.BigEndian.Uint32(d[1:5])
	var initialType byte
	switch version {
	case quicV1:
		initialType = 0
	case quicV2:
		initialType = 1
	default:
		return 0, nil, false, false
	}
	p := 5
	dl := int(d[p])
	p++
	if dl > 20 || len(d) < p+dl+1 {
		return 0, nil, false, false
	}
	dcid := d[p : p+dl]
	p += dl
	sl := int(d[p])
	p++
	if sl > 20 || len(d) < p+sl {
		return 0, nil, false, false
	}
	p += sl
	typ := (d[0] >> 4) & 3
	if typ == initialType {
		tl, k := quicVarint(d[p:])
		if k == 0 || uint64(len(d)-p-k) < tl {
			return 0, nil, false, false
		}
		p += k + int(tl)
	}
	length, k := quicVarint(d[p:])
	if k == 0 || uint64(len(d)-p-k) < length {
		return 0, nil, false, false
	}
	pnOff := p + k
	n = pnOff + int(length)
	if typ != initialType {
		return n, nil, false, true
	}
	frames, ok = quicOpen(version, dcid, d[:n], pnOff)
	if !ok {
		return n, nil, false, true
	}
	return n, frames, true, true
}

// quicOpen removes header protection and decrypts a client Initial packet.
func quicOpen(version uint32, dcid, pkt []byte, pnOff int) ([]byte, bool) {
	key, iv, hp := quicInitialKeys(version, dcid)
	if len(pkt) < pnOff+4+16 {
		return nil, false
	}
	hb, err := aes.NewCipher(hp)
	if err != nil {
		return nil, false
	}
	var mask [16]byte
	hb.Encrypt(mask[:], pkt[pnOff+4:pnOff+20])
	hdr := append([]byte(nil), pkt[:pnOff+4]...)
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&3) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOff+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[pnOff+i])
	}
	hdr = hdr[:pnOff+pnLen]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	out, err := aead.Open(nil, nonce, pkt[pnOff+pnLen:], hdr)
	if err != nil {
		return nil, false
	}
	return out, true
}

// quicInitialKeys derives the client's Initial keys (RFC 9001 5.2, RFC
// 9369 3.3.1 for version 2).
func quicInitialKeys(version uint32, dcid []byte) (key, iv, hp []byte) {
	salt, kl, il, hl := quicSaltV1, "quic key", "quic iv", "quic hp"
	if version == quicV2 {
		salt, kl, il, hl = quicSaltV2, "quicv2 key", "quicv2 iv", "quicv2 hp"
	}
	initial := hkdf.Extract(sha256.New, dcid, salt)
	client := expandLabel(initial, "client in", 32)
	return expandLabel(client, kl, 16), expandLabel(client, il, 12), expandLabel(client, hl, 16)
}

// expandLabel is TLS 1.3's HKDF-Expand-Label with an empty context.
func expandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out := make([]byte, n)
	_, _ = io.ReadFull(hkdf.Expand(sha256.New, secret, info), out)
	return out
}
