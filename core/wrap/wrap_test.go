package wrap

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDeriveKeyMatchesServer(t *testing.T) {
	// The same vector as the wdtt-router server test (HKDF-SHA256, RFC 5869).
	k, err := DeriveKey("password")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(k) != "eb03366b47491332578610f3b1474739788893712b1172158c803b3ad2011fa3" {
		t.Fatalf("key %x", k)
	}
}

func TestRoundTrip(t *testing.T) {
	a, _ := NewAEAD("pw")
	other, _ := NewAEAD("other")
	for _, mode := range []Mode{Audio, Video} {
		s := NewSealer(a, mode)
		for _, n := range []int{1, 100, 1400} {
			p := bytes.Repeat([]byte{byte(n)}, n)
			wire := make([]byte, s.SealedLen(n))
			w := s.Seal(wire, p)
			out := make([]byte, 2048)
			m, err := Open(a, wire[:w], out)
			if err != nil || !bytes.Equal(out[:m], p) {
				t.Fatalf("mode %d len %d: %v", mode, n, err)
			}
			if _, err := Open(other, wire[:w], out); err == nil {
				t.Fatal("opened with the wrong key")
			}
			if wire[1] != PTAudio && wire[1] != PTVideo {
				t.Fatal("payload type")
			}
		}
	}
}
