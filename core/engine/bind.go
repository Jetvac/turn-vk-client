package engine

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/Jetvac/turn-vk-client/core/session"
)

// bind connects WireGuard straight to the transport sessions: there is no
// local UDP socket. Each outgoing packet goes on the session where it would
// arrive first (see pick): small packets never wait behind an upload, big
// ones spread over all sessions.
type bind struct {
	recv chan []byte

	mu     sync.Mutex
	closed chan struct{}

	sessions atomic.Pointer[[]*session.Session]

	pacer    *pacer
	reorder  Reorder[[]byte] // what the server spreads over many sessions, in order again
	pacedAt  atomic.Int64    // unix ns of the last check whether to pace
	pacedNow atomic.Bool

	qmu    sync.Mutex
	queues map[*session.Session]*pathQueue
	last   *session.Session // session of the last bulk packet
	run    int              // bulk packets in a row on it

	dropped atomic.Uint64
	rx      atomic.Uint64
	tx      atomic.Uint64
	// bytes: the tunnel's packets both ways, copies aside (routes on
	// demand, idle.go).
	bytes atomic.Uint64

	// quiet: the engine's idle mode (nil without one): a packet sent
	// while idle brings the routes' next ping burst forward.
	quiet *session.Quiet

	// For the statistics: how long held packets waited in the reorder
	// buffer, and small packets in the pacer's queue.
	holds, qwait session.Hist
}

const (
	batchSize = 32
	recvQueue = 2048
)

var errNoSession = errors.New("no transport session")

func newBind() *bind {
	b := &bind{recv: make(chan []byte, recvQueue), closed: make(chan struct{}), queues: map[*session.Session]*pathQueue{}}
	b.pacer = newPacer(b)
	b.reorder.Out = b.deliver
	b.reorder.Waited = b.holds.Add
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
	b.qmu.Lock()
	delete(b.queues, s)
	if b.last == s {
		b.last = nil
	}
	b.qmu.Unlock()
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
	b.bytes.Add(uint64(len(pkt)))
	select {
	case b.recv <- pkt:
	default:
		b.dropped.Add(1)
		putBuf(pkt)
	}
}

// gaps returns how many gaps the reorder buffer gave up on so far.
func (b *bind) gaps() uint64 {
	b.reorder.mu.Lock()
	defer b.reorder.mu.Unlock()
	return b.reorder.Gaps
}

// deliverOrdered is deliver for packets of a TurnVK server, which spreads
// them over all sessions: WireGuard data goes through the reorder buffer.
func (b *bind) deliverOrdered(pkt []byte) {
	if idx, ctr, ok := WGData(pkt); ok {
		b.reorder.Push(idx, ctr, pkt)
		return
	}
	b.deliver(pkt)
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
	now := time.Now()
	b.quiet.Nudge(now)
	if b.paced(list, now) {
		b.pacer.enqueue(bufs)
		return nil
	}
	var arr [batchSize]*session.Session
	plan := arr[:0]
	if len(bufs) > len(arr) {
		plan = make([]*session.Session, 0, len(bufs))
	}
	b.qmu.Lock()
	for _, p := range bufs {
		plan = append(plan, b.pick(list, len(p), now))
	}
	b.qmu.Unlock()
	for i, p := range bufs {
		if s := plan[i]; s != nil && s.Write(p) == nil {
			b.tx.Add(1)
			b.bytes.Add(uint64(len(p)))
			continue
		} else if s != nil {
			s.Close()
		}
		if err := b.sendAny(list, p, plan[i]); err != nil {
			return err
		}
	}
	return nil
}

// paced reports whether some session's server sends FEEDBACK, so that
// uploads go through the pacer (pacer.go). Checked every 200 ms.
func (b *bind) paced(list []*session.Session, now time.Time) bool {
	ns := now.UnixNano()
	if ns-b.pacedAt.Load() < int64(200*time.Millisecond) {
		return b.pacedNow.Load()
	}
	b.pacedAt.Store(ns)
	on := false
	for _, s := range list {
		if !s.Closed() && s.Pace.HasFeedback() {
			on = true
			break
		}
	}
	b.pacedNow.Store(on)
	return on
}

// sendAny sends on any open session but skip, for when the chosen one failed.
func (b *bind) sendAny(list []*session.Session, p []byte, skip *session.Session) error {
	for _, s := range list {
		if s == skip || s.Closed() {
			continue
		}
		if err := s.Write(p); err == nil {
			b.tx.Add(1)
			b.bytes.Add(uint64(len(p)))
			return nil
		}
		s.Close()
	}
	return errNoSession
}

// pick chooses the session for one packet of n bytes and books it there:
// the one it would arrive first on, given what is queued on each (VK
// relays an allocation at about pathRate) and its round trip. Sessions
// that do not answer are used only when none does. Called with qmu held.
func (b *bind) pick(list []*session.Session, n int, now time.Time) *session.Session {
	ns := now.UnixNano()
	var best *session.Session
	var bestQ *pathQueue
	bestD := 0.0
	for pass := 0; pass < 2 && best == nil; pass++ {
		for _, s := range list {
			if s.Closed() || (pass == 0 && !s.Fresh(now)) {
				continue
			}
			q := b.queue(s)
			d := q.arrival(ns, pathRTT(s, n))
			if best == nil || d < bestD {
				best, bestQ, bestD = s, q, d
			}
		}
	}
	if best == nil {
		return nil
	}
	if n >= bulkSize {
		if l := b.last; l != nil && l != best && b.run < bulkRun && !l.Closed() && l.Fresh(now) {
			if q := b.queue(l); q.arrival(ns, l.RTT.Load()) <= bestD+stickSlack {
				best, bestQ = l, q
			}
		}
		if best == b.last {
			b.run++
		} else {
			b.last, b.run = best, 1
		}
	}
	bestQ.add(ns, n+wireOverhead)
	return best
}

// pathRTT is the round trip pick counts on for a packet of n bytes: for
// small ones (games, calls, ACKs) the one jitter included, so that a path
// whose last ping was lucky but which often spikes is not chosen (on a
// phone's mobile network the slowest pings were eight times the typical
// one); big ones go by the last ping.
func pathRTT(s *session.Session, n int) int64 {
	if n < bulkSize {
		if l := s.Lat.Load(); l > 0 {
			return l
		}
	}
	return s.RTT.Load()
}

func (b *bind) queue(s *session.Session) *pathQueue {
	q := b.queues[s]
	if q == nil {
		q = &pathQueue{}
		b.queues[s] = q
	}
	return q
}

// pathQueue models the bytes a session has yet to deliver: VK relays each
// allocation at about pathRate, anything sent faster waits in its queue.
type pathQueue struct {
	bytes float64
	at    int64 // unix ns of the last update
}

const (
	pathRate     = 175_000.0 // bytes/s one VK allocation relays (~1.4 Mbit/s, measured)
	bulkSize     = 512       // smaller packets are latency-sensitive
	bulkRun      = 4         // bulk packets kept on one session in a row
	stickSlack   = 0.025     // s: how much later a bulk packet may arrive to stay on its session
	wireOverhead = 40        // RTP header, tag, TURN ChannelData
)

func (q *pathQueue) backlog(now int64) float64 {
	b := q.bytes - pathRate*float64(now-q.at)/1e9
	if b < 0 {
		return 0
	}
	return b
}

func (q *pathQueue) add(now int64, n int) {
	q.bytes = q.backlog(now) + float64(n)
	q.at = now
}

// arrival estimates in seconds when a packet sent now gets through.
func (q *pathQueue) arrival(now int64, rtt int64) float64 {
	return q.backlog(now)/pathRate + float64(rtt)/2e9
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
