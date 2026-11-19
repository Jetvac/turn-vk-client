package engine

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Jetvac/turn-vk-client/core/session"
)

// The pacer sends what the device uploads over the sessions whose server
// reports how packets come through (FEEDBACK, see session/pace.go), each
// at the rate VK lets through, so that the queue forms here rather than
// as loss at VK:
//   - small packets (TCP ACKs, DNS, pings, games, calls) go first, and the
//     smallest go on two sessions at once, through two different VK TURN
//     servers when there are: whichever arrives first counts, WireGuard
//     drops the other as a replay; a relay that stalls does not stall both;
//   - bulk packets stay on one session until its tokens run out: the TCP
//     sender is on this device, and many stacks (gVisor's in the CLI, older
//     Windows and Android ones) take reordering for loss and slow down
//     (measured: twice the upload speed of runs of 4 packets);
//   - bulk packets that have waited longer than maxQueueDelay are dropped,
//     which tells TCP to slow down before a long queue builds;
//   - while small packets flow steadily (a game, a call: session.Interactive)
//     queues are kept shorter: bulk packets wait at most TightBulkWait, and
//     each path keeps VK's queue short (PathRate.Tight).
//
// Sessions to servers that send no FEEDBACK (standard servers, older
// TurnVK servers) are not paced: packets go out at once, as before.
const (
	maxQueueDelay = 60 * time.Millisecond
	maxQueueBytes = 4 << 20
	smallPacket   = 512 // smaller packets are latency-sensitive
	dupPacket     = 400 // smaller packets go on two sessions (most game packets)
	pacerIdleExit = time.Minute
)

type queued struct {
	b  []byte
	at int64
}

type sendItem struct {
	s   *session.Session
	b   []byte
	dup bool // the first copy owns the buffer
}

type pacer struct {
	b *bind

	mu      sync.Mutex
	hi, lo  []queued
	loBytes int
	last    *session.Session
	run     int
	running bool
	idle    int64 // unix ns since the queue is empty

	wake    chan struct{}
	dropped atomic.Uint64
	other   []*session.Session // pickCopy's scratch, under mu
	inter   session.Interactive
}

func newPacer(b *bind) *pacer { return &pacer{b: b, wake: make(chan struct{}, 1)} }

// enqueue copies the packets in (WireGuard reuses its buffers).
func (p *pacer) enqueue(bufs [][]byte) {
	now := time.Now().UnixNano()
	p.mu.Lock()
	small := 0
	for _, x := range bufs {
		if len(x) < smallPacket {
			small++
		}
		if len(x) > 2048 {
			continue
		}
		c := getBuf()[:len(x)]
		copy(c, x)
		if len(x) < smallPacket {
			p.hi = append(p.hi, queued{c, now})
		} else if p.loBytes+len(x) <= maxQueueBytes {
			p.lo = append(p.lo, queued{c, now})
			p.loBytes += len(x)
		} else {
			putBuf(c)
			p.dropped.Add(1)
		}
	}
	p.inter.Note(now, small)
	start := !p.running
	p.running = true
	p.mu.Unlock()
	if start {
		go p.loop()
	}
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *pacer) loop() {
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	var out []sendItem
	for {
		var wait time.Duration
		out, wait = p.step(out[:0])
		for _, it := range out {
			if err := it.s.Write(it.b); err == nil {
				p.b.tx.Add(1)
			} else if !it.dup {
				it.s.Close()
				_ = p.b.sendAny(p.b.list(), it.b, it.s)
			}
		}
		for _, it := range out {
			if !it.dup {
				putBuf(it.b)
			}
		}
		if wait < 0 {
			return
		}
		if len(out) > 0 && wait == 0 {
			continue
		}
		if wait == 0 {
			wait = time.Hour
		}
		t.Reset(wait)
		select {
		case <-t.C:
		case <-p.wake:
		}
	}
}

// step picks the packets that can go now; wait is how long until the next
// one can (0: queue empty; <0: the pacer goroutine ends).
func (p *pacer) step(out []sendItem) ([]sendItem, time.Duration) {
	now := time.Now()
	ns := now.UnixNano()
	all := p.b.list()
	var list []*session.Session
	for _, s := range all {
		if !s.Closed() && s.Fresh(now) && s.Pace.HasFeedback() {
			list = append(list, s)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.hi)+len(p.lo) == 0 {
		if p.idleSince(ns) > pacerIdleExit {
			p.running = false
			return out, -1
		}
		return out, 0
	}
	p.idle = 0
	if len(list) == 0 {
		// No paced session (any more): send at once on any open one.
		for _, q := range append(p.hi, p.lo...) {
			if s := firstOpen(all); s != nil {
				out = append(out, sendItem{s: s, b: q.b})
			} else {
				putBuf(q.b)
			}
		}
		p.hi, p.lo, p.loBytes = nil, nil, 0
		return out, 0
	}
	tight := p.inter.Note(ns, 0)
	for _, s := range list {
		s.Pace.Tight.Store(tight)
		s.Pace.Refill(ns)
	}
	cut := ns - int64(maxQueueDelay)
	if tight {
		cut = ns - int64(session.TightBulkWait)
	}
	for len(p.lo) > 0 && p.lo[0].at < cut {
		p.loBytes -= len(p.lo[0].b)
		putBuf(p.lo[0].b)
		p.lo = p.lo[1:]
		p.dropped.Add(1)
	}
	for len(p.hi) > 0 {
		q := p.hi[0]
		s := p.pick(list, len(q.b), nil, false)
		if s == nil {
			break
		}
		p.b.qwait.Add(time.Duration(ns - q.at))
		out = append(out, sendItem{s: s, b: q.b})
		if len(q.b) < dupPacket {
			if s2 := p.pickCopy(list, len(q.b), s); s2 != nil {
				out = append(out, sendItem{s: s2, b: q.b, dup: true})
			}
		}
		p.hi = p.hi[1:]
	}
	for len(p.hi) == 0 && len(p.lo) > 0 {
		s := p.pick(list, len(p.lo[0].b), nil, true)
		if s == nil {
			break
		}
		out = append(out, sendItem{s: s, b: p.lo[0].b})
		p.loBytes -= len(p.lo[0].b)
		p.lo = p.lo[1:]
	}
	var head int
	switch {
	case len(p.hi) > 0:
		head = len(p.hi[0].b)
	case len(p.lo) > 0:
		head = len(p.lo[0].b)
	default:
		p.hi, p.lo = nil, nil
		return out, 0
	}
	best := time.Duration(math.MaxInt64)
	for _, s := range list {
		s.Pace.Limited.Store(true)
		best = min(best, s.Pace.Wait(float64(head+wireOverhead)))
	}
	return out, max(best, 200*time.Microsecond)
}

// pick returns the session that can send n bytes now and gets them there
// first (not skip), and books the bytes on it; nil if none has the tokens.
func (p *pacer) pick(list []*session.Session, n int, skip *session.Session, bulk bool) *session.Session {
	size := float64(n + wireOverhead)
	var best *session.Session
	bestScore := 0.0
	for _, s := range list {
		if s == skip || s.Pace.Tokens < size {
			continue
		}
		// Half the round trip plus what waits ahead of the packet: an
		// idle path with the shortest round trip first; under load the
		// spare paths (spreads it).
		score := float64(s.RTT.Load())/2e9 + s.Pace.Queued()
		if best == nil || score < bestScore {
			best, bestScore = s, score
		}
	}
	if best == nil {
		return nil
	}
	if bulk {
		if l := p.last; l != nil && l != best && !l.Closed() && l.Pace.Tokens >= size && contains(list, l) {
			best = l
		}
		if best == p.last {
			p.run++
		} else {
			p.last, p.run = best, 1
		}
	}
	best.Pace.Tokens -= size
	return best
}

// pickCopy picks the session for the copy of a small packet that went on
// s: through another VK TURN server if one can send now, else any other.
func (p *pacer) pickCopy(list []*session.Session, n int, s *session.Session) *session.Session {
	p.other = p.other[:0]
	for _, x := range list {
		if x.Server != s.Server {
			p.other = append(p.other, x)
		}
	}
	if x := p.pick(p.other, n, nil, false); x != nil {
		return x
	}
	return p.pick(list, n, s, false)
}

func (p *pacer) idleSince(now int64) time.Duration {
	if p.idle == 0 {
		p.idle = now
	}
	return time.Duration(now - p.idle)
}

func firstOpen(list []*session.Session) *session.Session {
	for _, s := range list {
		if !s.Closed() {
			return s
		}
	}
	return nil
}

func contains(list []*session.Session, s *session.Session) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
