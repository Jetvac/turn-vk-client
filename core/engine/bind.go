package engine

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/Jetvac/turn-vk-client/core/session"
)

// bind connects WireGuard straight to the transport sessions: there is no
// local UDP socket. Outgoing packets go to one session for a run of
// `chunk` packets, then to the next; a lightly loaded tunnel therefore uses
// one relay at a time (no reordering), a busy one spreads over all of them.
type bind struct {
	recv chan []byte

	mu     sync.Mutex
	closed chan struct{}

	sessions atomic.Pointer[[]*session.Session]
	cur      atomic.Uint32
	run      atomic.Uint32

	dropped atomic.Uint64
	rx      atomic.Uint64
	tx      atomic.Uint64
}

const (
	chunk     = 16
	batchSize = 32
	recvQueue = 2048
)

var errNoSession = errors.New("no transport session")

func newBind() *bind {
	b := &bind{recv: make(chan []byte, recvQueue), closed: make(chan struct{})}
	empty := []*session.Session{}
	b.sessions.Store(&empty)
	return b
}

func (b *bind) add(s *session.Session) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	old := *b.sessions.Load()
	next := make([]*session.Session, 0, len(old)+1)
	next = append(next, old...)
	next = append(next, s)
	b.sessions.Store(&next)
	return len(next)
}

func (b *bind) remove(s *session.Session) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	old := *b.sessions.Load()
	next := make([]*session.Session, 0, len(old))
	for _, x := range old {
		if x != s {
			next = append(next, x)
		}
	}
	b.sessions.Store(&next)
	return len(next)
}

func (b *bind) list() []*session.Session { return *b.sessions.Load() }

func (b *bind) has(s *session.Session) bool {
	for _, x := range b.list() {
		if x == s {
			return true
		}
	}
	return false
}

// deliver hands a packet read from a session to WireGuard. pkt is owned by
// the bind afterwards.
func (b *bind) deliver(pkt []byte) {
	b.rx.Add(1)
	select {
	case b.recv <- pkt:
	default:
		b.dropped.Add(1)
		putBuf(pkt)
	}
}

func (b *bind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	select {
	case <-b.closed:
		b.closed = make(chan struct{})
	default:
	}
	closed := b.closed
	b.mu.Unlock()
	fn := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		var pkt []byte
		select {
		case pkt = <-b.recv:
		case <-closed:
			return 0, net.ErrClosed
		}
		n := 0
		for {
			sizes[n] = copy(bufs[n], pkt)
			eps[n] = endpoint{}
			putBuf(pkt)
			n++
			if n == len(bufs) {
				return n, nil
			}
			select {
			case pkt = <-b.recv:
			default:
				return n, nil
			}
		}
	}
	return []conn.ReceiveFunc{fn}, 0, nil
}

func (b *bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	return nil
}

func (b *bind) SetMark(uint32) error { return nil }
func (b *bind) BatchSize() int       { return batchSize }

func (b *bind) ParseEndpoint(string) (conn.Endpoint, error) { return endpoint{}, nil }

func (b *bind) Send(bufs [][]byte, _ conn.Endpoint) error {
	list := b.list()
	if len(list) == 0 {
		return errNoSession
	}
	for _, p := range bufs {
		if err := b.sendOne(list, p); err != nil {
			return err
		}
	}
	return nil
}

func (b *bind) sendOne(list []*session.Session, p []byte) error {
	n := uint32(len(list))
	start := b.cur.Load() % n
	if b.run.Add(1) > chunk {
		b.run.Store(1)
		start = (start + 1) % n
		b.cur.Store(start)
	}
	for i := uint32(0); i < n; i++ {
		s := list[(start+i)%n]
		if s.Closed() {
			continue
		}
		if err := s.Write(p); err == nil {
			b.tx.Add(1)
			if i > 0 {
				b.cur.Store((start + i) % n)
				b.run.Store(1)
			}
			return nil
		}
		s.Close()
	}
	return errNoSession
}

// endpoint is the only peer address: the server, reached through sessions.
type endpoint struct{}

func (endpoint) ClearSrc()           {}
func (endpoint) SrcToString() string { return "" }
func (endpoint) DstToString() string { return "wdtt" }
func (endpoint) DstToBytes() []byte  { return []byte("wdtt") }
func (endpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (endpoint) SrcIP() netip.Addr   { return netip.Addr{} }

var bufs = sync.Pool{New: func() any { return make([]byte, 2048) }}

func getBuf() []byte { return bufs.Get().([]byte)[:2048] }
func putBuf(b []byte) {
	if cap(b) >= 2048 {
		bufs.Put(b[:2048]) //nolint:staticcheck // slices are fine here
	}
}
