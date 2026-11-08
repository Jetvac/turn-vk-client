// Package wrap disguises datagrams as encrypted RTP media packets, in the
// format WDTT servers expect:
//
//	RTP v2 header (12 bytes, padding bit set, PT 111 audio / 96 video)
//	ChaCha20-Poly1305(payload), the header as additional data
//	1..N padding bytes, the count in the last byte
//
//	nonce = SSRC(4) | seq(2) | 0x0000 | timestamp(4)
//	key   = HKDF-SHA256(password, salt "WDTT-WRAP-v1", info "rtp-obfs/chacha20poly1305")
package wrap

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	HeaderLen = 12
	TagLen    = chacha20poly1305.Overhead
	PTAudio   = 111
	PTVideo   = 96
	// MaxOverhead is the most Seal adds to a payload.
	MaxOverhead = HeaderLen + TagLen + 60
)

// Mode selects the RTP payload type and the padding range.
type Mode int

const (
	Audio Mode = iota
	Video
)

// ParseMode reads "audio" or "video" (anything else is audio).
func ParseMode(s string) Mode {
	if s == "video" {
		return Video
	}
	return Audio
}

// DeriveKey returns the wrap key for a connection password.
func DeriveKey(password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("empty password")
	}
	key := make([]byte, chacha20poly1305.KeySize)
	r := hkdf.New(sha256.New, []byte(password), []byte("WDTT-WRAP-v1"), []byte("rtp-obfs/chacha20poly1305"))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// NewAEAD returns the cipher for a connection password.
func NewAEAD(password string) (cipher.AEAD, error) {
	k, err := DeriveKey(password)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.New(k)
}

func nonceFor(hdr []byte) [12]byte {
	var n [12]byte
	copy(n[0:4], hdr[8:12])
	copy(n[4:6], hdr[2:4])
	copy(n[8:12], hdr[4:8])
	return n
}

// Open authenticates and decrypts one wrapped datagram into dst.
func Open(aead cipher.AEAD, wire, dst []byte) (int, error) {
	if len(wire) < HeaderLen+TagLen+1 || wire[0]>>6 != 2 {
		return 0, errors.New("not an RTP packet")
	}
	if pt := wire[1] & 0x7f; pt != PTAudio && pt != PTVideo {
		return 0, errors.New("unexpected RTP payload type")
	}
	end := len(wire)
	if wire[0]&0x20 != 0 {
		pad := int(wire[end-1])
		if pad == 0 || pad > end-HeaderLen {
			return 0, errors.New("bad RTP padding")
		}
		end -= pad
	}
	ct := wire[HeaderLen:end]
	if len(ct) <= TagLen || len(ct)-TagLen > len(dst) {
		return 0, errors.New("bad payload length")
	}
	n := nonceFor(wire)
	out, err := aead.Open(dst[:0], n[:], ct, wire[:HeaderLen])
	if err != nil {
		return 0, err
	}
	return len(out), nil
}

// Sealer wraps the outgoing datagrams of one stream. Sequence numbers and
// timestamps advance like a 48 kHz Opus stream with 20 ms frames; the
// (seq, ts) pair stays unique for 2^48 packets, so nonces never repeat
// within a stream, and every stream has a random SSRC.
type Sealer struct {
	aead   cipher.AEAD
	ssrc   uint32
	pt     byte
	padMax int
	seq0   uint16
	ts0    uint32
	n      atomic.Uint64
}

// NewSealer starts a new stream.
func NewSealer(aead cipher.AEAD, mode Mode) *Sealer {
	s := &Sealer{aead: aead, pt: PTAudio, padMax: 24, ssrc: rand.Uint32(), seq0: uint16(rand.Uint32()), ts0: rand.Uint32()}
	if mode == Video {
		s.pt, s.padMax = PTVideo, 60
	}
	return s
}

// SealedLen is the largest size Seal can produce for a payload.
func (s *Sealer) SealedLen(payload int) int { return HeaderLen + payload + TagLen + s.padMax }

// Seal writes the wrapped form of payload into dst and returns its length.
// dst must hold SealedLen(len(payload)) bytes and must not overlap payload.
func (s *Sealer) Seal(dst, payload []byte) int {
	c := s.n.Add(1) - 1
	seq := s.seq0 + uint16(c)
	ts := s.ts0 + uint32(c)*960 + uint32(c>>16)
	dst[0] = 0x80 | 0x20
	dst[1] = s.pt
	binary.BigEndian.PutUint16(dst[2:4], seq)
	binary.BigEndian.PutUint32(dst[4:8], ts)
	binary.BigEndian.PutUint32(dst[8:12], s.ssrc)
	n := nonceFor(dst)
	out := s.aead.Seal(dst[HeaderLen:HeaderLen], n[:], payload, dst[:HeaderLen])
	end := HeaderLen + len(out)
	pad := 1 + rand.IntN(s.padMax)
	r := rand.Uint64()
	for i := 0; i < pad-1; i++ {
		if i%8 == 0 && i > 0 {
			r = rand.Uint64()
		}
		dst[end+i] = byte(r >> (8 * (i % 8)))
	}
	dst[end+pad-1] = byte(pad)
	return end + pad
}
