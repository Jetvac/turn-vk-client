package session

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Jetvac/turn-vk-client/core/wrap"
)

// fakeServer answers each HELLO with the status status(n) gives the n-th
// one, and keeps the HELLOs.
type fakeServer struct {
	conn   *net.UDPConn
	mu     sync.Mutex
	hellos [][]byte
}

func newFakeServer(t *testing.T, password string, status func(n int) byte) *fakeServer {
	t.Helper()
	aead, err := wrap.NewAEAD(password)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	f := &fakeServer{conn: conn}
	go func() {
		sealer := wrap.NewSealer(aead, wrap.Audio)
		buf, msg, out := make([]byte, 4096), make([]byte, 4096), make([]byte, 4096)
		for n := 0; ; {
			k, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			m, err := wrap.Open(aead, buf[:k], msg)
			if err != nil || m < 60 || msg[0] != msgHello {
				continue
			}
			f.mu.Lock()
			f.hellos = append(f.hellos, append([]byte(nil), msg[:m]...))
			f.mu.Unlock()
			st := status(n)
			n++
			reply := append([]byte{msgWelcome, directVersion}, msg[10:26]...)
			reply = append(reply, st)
			if st == welcomeOK {
				reply = append(reply, make([]byte, 41)...)
			}
			w := sealer.Seal(out, reply)
			_, _ = conn.WriteTo(out[:w], from)
		}
	}()
	return f
}

func (f *fakeServer) sent() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.hellos...)
}

func dialFake(t *testing.T, f *fakeServer, password string) error {
	t.Helper()
	aead, _ := wrap.NewAEAD(password)
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relay.Close() })
	s := &Session{relay: relay, done: make(chan struct{})}
	p := Params{AEAD: aead, Mode: wrap.Audio, Peer: f.conn.LocalAddr().(*net.UDPAddr), Keys: &Keys{},
		DeviceID: "phone", Generation: "run-2", RunAt: 1795812345678}
	return s.dialDirect(p, 3*time.Second)
}

// A HELLO refused because a newer connection of the device holds it (the
// app's previous run crossing it, or a clock that stepped back) is sent
// again, fresh; only refusals that go on end the attempt.
func TestStaleHelloSentAgain(t *testing.T) {
	old := staleRetry
	staleRetry = 20 * time.Millisecond
	t.Cleanup(func() { staleRetry = old })

	f := newFakeServer(t, "pw", func(n int) byte {
		if n < 2 {
			return welcomeStale
		}
		return welcomeOK
	})
	if err := dialFake(t, f, "pw"); err != nil {
		t.Fatalf("refused twice, then welcomed: %v", err)
	}
	h := f.sent()
	if len(h) != 3 {
		t.Fatalf("%d HELLOs, want 3", len(h))
	}
	if string(h[0][10:26]) == string(h[1][10:26]) || binary.BigEndian.Uint64(h[1][2:10]) < binary.BigEndian.Uint64(h[0][2:10]) {
		t.Fatal("the HELLO sent again is not a fresh one")
	}
	// The run's start follows the generation, flagged.
	last := h[2]
	if last[58]&helloRunAt == 0 || binary.BigEndian.Uint64(last[len(last)-8:]) != 1795812345678 {
		t.Fatalf("no run start in the HELLO: flags %x", last[58])
	}

	f = newFakeServer(t, "pw", func(int) byte { return welcomeStale })
	err := dialFake(t, f, "pw")
	var d *DeniedError
	if !errors.As(err, &d) || d.Reason != "newer_connection" {
		t.Fatalf("always refused: %v", err)
	}
	if n := len(f.sent()); n != 1+staleTries {
		t.Fatalf("%d HELLOs, want %d", n, 1+staleTries)
	}
}
