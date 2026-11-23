package engine

// This file is shared by the TurnVK server (wdtt-router, internal/wdtt) and
// the TurnVK client (turn-vk-client, core/engine); only the package line
// differs. Keep the two copies the same.
//
// Spread over many routes, WireGuard packets arrive out of order, and many
// TCP stacks take reordering for loss and slow down. A WireGuard data
// packet carries its receiver index and counter in the clear, so the
// receiving side puts them back in order before WireGuard sees them: a
// packet that comes early waits until the ones before it arrive, at most
// ReorderHold; then whatever is held goes on in order and the gap is
// counted as lost. Late packets and duplicates pass at once (WireGuard
// drops replays itself).
//
// On a lossy link most gaps are losses: waiting the whole hold for each
// delays everything behind it for nothing (the stats: a phone on a lossy
// evening link gave up on 50-360 gaps a minute, each after the full
// hold). An adaptive Reorder (Adapt) measures how late the packets that do
// fill gaps come, those that came after it gave up included, and holds
// about as long as they need, between ReorderHoldMin and Hold.

import (
	"encoding/binary"
	"sort"
	"sync"
	"time"
)

const (
	ReorderHold  = 10 * time.Millisecond
	reorderMax   = 512             // packets held per stream before giving up
	reorderJump  = 4096            // a counter this far ahead starts afresh
	reorderStale = 2 * time.Minute // streams unused this long are forgotten

	// ReorderHoldMin: the shortest hold of an adaptive Reorder.
	ReorderHoldMin = 2 * time.Millisecond
	// reorderSamples: how late the latest gap-filling packets came, the
	// adaptive hold goes by these.
	reorderSamples = 256
	// reorderTune: the hold is worked out again every so many events
	// (gaps filled, given up on, or filled after that), once there were
	// twice as many.
	reorderTune = 16
	// reorderMissed, reorderMissAge: counters given up on, remembered per
	// stream this many and this long, to tell a late packet from a lost
	// one.
	reorderMissed  = 256
	reorderMissAge = 200 * time.Millisecond
)

// WGData returns the receiver index and counter of a WireGuard transport
// data packet; ok is false for other messages.
func WGData(p []byte) (idx uint32, counter uint64, ok bool) {
	if len(p) < 32 || p[0] != 4 || p[1] != 0 || p[2] != 0 || p[3] != 0 {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint32(p[4:8]), binary.LittleEndian.Uint64(p[8:16]), true
}

// Reorder puts WireGuard data packets back in counter order, per receiver
// index. Out is called with each item in order, from Push or from a timer.
type Reorder[T any] struct {
	Out  func(T)
	Hold time.Duration // 0: ReorderHold
	// Waited, if set, gets how long each held item waited (called with
	// the lock held: it must not block or call back).
	Waited func(time.Duration)
	// Adapt: the hold follows how late gap-filling packets come, between
	// ReorderHoldMin and Hold (see above). Set before the first Push.
	Adapt bool

	mu      sync.Mutex
	streams map[uint32]*reorderStream[T]
	// outMu keeps Out calls in order: it is taken before mu is let go,
	// so that items one Push (or timer) hands on are out before those of
	// the next, which may run on another route's goroutine.
	outMu  sync.Mutex
	pushes int

	Held, Late, Gaps uint64 // counters, under mu

	// The adaptive hold, under mu: the latest samples of how late a
	// gap-filling packet came, the events since the start, the hold now
	// (0: not worked out yet).
	late   [reorderSamples]time.Duration
	nLate  int
	events int
	cur    time.Duration
}

type reorderStream[T any] struct {
	next  uint64 // the counter expected next
	held  map[uint64]heldItem[T]
	timer *time.Timer
	used  time.Time
	// since: when the timer started (the wait for the gap began);
	// missed: counters given up on, and their since (adaptive hold).
	since  time.Time
	missed map[uint64]time.Time
}

// Push hands one item on, now or once the packets before it arrived.
func (r *Reorder[T]) Push(idx uint32, counter uint64, item T) {
	var out []T
	r.mu.Lock()
	if r.streams == nil {
		r.streams = map[uint32]*reorderStream[T]{}
	}
	now := time.Now()
	r.pushes++
	if r.pushes%4096 == 0 {
		for k, s := range r.streams {
			if len(s.held) == 0 && now.Sub(s.used) > reorderStale {
				delete(r.streams, k)
			}
		}
	}
	s := r.streams[idx]
	if s == nil {
		s = &reorderStream[T]{next: counter, held: map[uint64]heldItem[T]{}}
		r.streams[idx] = s
	}
	s.used = now
	switch {
	case counter == s.next:
		if r.Adapt && len(s.held) > 0 {
			r.noteLate(now.Sub(s.since)) // a gap filled
		}
		out = append(out, item)
		s.next++
		out = s.drain(out, r.Waited, now)
	case counter < s.next:
		r.Late++
		if t, ok := s.missed[counter]; ok && r.Adapt {
			delete(s.missed, counter)
			r.noteLate(now.Sub(t)) // came after the gap was given up on
		}
		out = append(out, item) // late or a duplicate: WireGuard decides
	case counter-s.next > reorderJump || len(s.held) >= reorderMax:
		// Far ahead, or too much held: give up on the gap.
		r.giveUp(s, now)
		out = s.flush(out, r.Waited, now)
		r.Gaps++
		out = append(out, item)
		s.next = counter + 1
	default:
		if _, dup := s.held[counter]; !dup {
			s.held[counter] = heldItem[T]{item, now}
			r.Held++
		}
		if s.timer == nil {
			s.since = now
			s.timer = time.AfterFunc(r.hold(), func() { r.expire(idx, s) })
		}
	}
	if len(s.held) == 0 && s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	r.handOut(out)
}

// expire: the gap did not fill in time; send what is held, in order.
func (r *Reorder[T]) expire(idx uint32, s *reorderStream[T]) {
	r.mu.Lock()
	if r.streams[idx] != s {
		r.mu.Unlock()
		return
	}
	s.timer = nil
	var out []T
	if len(s.held) > 0 {
		r.Gaps++
		now := time.Now()
		r.giveUp(s, now)
		out = s.flush(nil, r.Waited, now)
	}
	r.handOut(out)
}

// hold: how long a gap is waited for now. r.mu is held.
func (r *Reorder[T]) hold() time.Duration {
	h := r.Hold
	if h <= 0 {
		h = ReorderHold
	}
	if r.Adapt && r.cur > 0 && r.cur < h {
		return r.cur
	}
	return h
}

// HoldNow: how long a gap is waited for now.
func (r *Reorder[T]) HoldNow() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hold()
}

// noteLate notes how late a gap-filling packet came. r.mu is held.
func (r *Reorder[T]) noteLate(d time.Duration) {
	r.late[r.nLate%reorderSamples] = d
	r.nLate++
	r.tune()
}

// giveUp notes the counters a flush of s skips, so that one coming later
// counts as late rather than lost (adaptive hold). r.mu is held.
func (r *Reorder[T]) giveUp(s *reorderStream[T], now time.Time) {
	if !r.Adapt || len(s.held) == 0 {
		return
	}
	if s.missed == nil {
		s.missed = map[uint64]time.Time{}
	}
	if len(s.missed) >= reorderMissed/2 {
		for c, t := range s.missed {
			if now.Sub(t) > reorderMissAge {
				delete(s.missed, c)
			}
		}
	}
	since := s.since
	if since.IsZero() {
		since = now
	}
	last := s.next
	for k := range s.held {
		last = max(last, k)
	}
	for c := s.next; c < last && len(s.missed) < reorderMissed; c++ {
		if _, ok := s.held[c]; !ok {
			s.missed[c] = since
		}
	}
	r.tune()
}

// tune counts an event and, every reorderTune of them, works the hold out
// again: about the 98th percentile of how late gap-filling packets came,
// with a margin. Gaps given up on with none filling later were losses:
// they bring the hold down to ReorderHoldMin. r.mu is held.
func (r *Reorder[T]) tune() {
	r.events++
	if r.events%reorderTune != 0 || r.events < 2*reorderTune {
		return
	}
	top := r.Hold
	if top <= 0 {
		top = ReorderHold
	}
	h := ReorderHoldMin
	if n := min(r.nLate, reorderSamples); n > 0 {
		s := make([]time.Duration, n)
		copy(s, r.late[:n])
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		q := s[(n-1)*98/100]
		h = max(h, q+q/4+500*time.Microsecond)
	}
	r.cur = min(h, top)
}

// handOut lets mu go and calls Out with each item, in order with the other
// calls. r.mu is held.
func (r *Reorder[T]) handOut(out []T) {
	if len(out) == 0 {
		r.mu.Unlock()
		return
	}
	r.outMu.Lock()
	r.mu.Unlock()
	defer r.outMu.Unlock()
	for _, it := range out {
		r.Out(it)
	}
}

type heldItem[T any] struct {
	it T
	at time.Time
}

// drain appends the held packets that follow on now.
func (s *reorderStream[T]) drain(out []T, waited func(time.Duration), now time.Time) []T {
	for {
		h, ok := s.held[s.next]
		if !ok {
			return out
		}
		delete(s.held, s.next)
		out = append(out, h.it)
		if waited != nil {
			waited(now.Sub(h.at))
		}
		s.next++
	}
}

// flush appends everything held, in counter order, and moves past it.
func (s *reorderStream[T]) flush(out []T, waited func(time.Duration), now time.Time) []T {
	if len(s.held) == 0 {
		return out
	}
	keys := make([]uint64, 0, len(s.held))
	for k := range s.held {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		h := s.held[k]
		out = append(out, h.it)
		if waited != nil {
			waited(now.Sub(h.at))
		}
		delete(s.held, k)
	}
	s.next = keys[len(keys)-1] + 1
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	return out
}
