package engine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// offlineGate holds new routes back while the device has no network
// (a phone in a lift, Wi-Fi gone and no mobile data): every allocation
// would fail at once ("network is unreachable"), costing battery and
// flooding the log. One route at a time tries again every offlineWait;
// the platform's network change (Reconnect) or a route that opens lets
// all of them go at once.
type offlineGate struct {
	mu     sync.Mutex
	until  time.Time     // offline until then (zero: online)
	wake   chan struct{} // closed when the network is back
	logged time.Time     // when "no network" was last logged
	// every: how often one route tries (offlineWait if zero); probing:
	// a route went to check and has not reported yet.
	every   time.Duration
	probing bool
}

// down notes that a route failed for lack of network; it returns true
// when that is news worth logging (at most once a minute).
func (g *offlineGate) down(now time.Time, d time.Duration) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.until = now.Add(d)
	if g.wake == nil {
		g.wake = make(chan struct{})
	}
	if now.Sub(g.logged) < time.Minute {
		return false
	}
	g.logged = now
	return true
}

// backoff is down with a wait of base, doubled (up to most) each time
// the route that went to check fails too; routes that failed together
// before the gate closed do not count.
func (g *offlineGate) backoff(now time.Time, base, most time.Duration) (time.Duration, bool) {
	g.mu.Lock()
	switch {
	case g.until.IsZero() || g.every == 0:
		g.every = base
	case g.probing:
		g.every = min(2*g.every, most)
	}
	g.probing = false
	d := g.every
	g.mu.Unlock()
	return d, g.down(now, d)
}

// up lets every waiting route go.
func (g *offlineGate) up() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.until.IsZero() {
		return
	}
	g.until = time.Time{}
	g.every, g.probing = 0, false
	if g.wake != nil {
		close(g.wake)
		g.wake = nil
	}
}

// wait returns once a route may try (false when ctx ends). While offline,
// the first route to find the wait over tries alone: the others wait
// another round unless it succeeds.
func (g *offlineGate) wait(ctx context.Context) bool {
	for {
		g.mu.Lock()
		if g.until.IsZero() {
			g.mu.Unlock()
			return ctx.Err() == nil
		}
		now := time.Now()
		if !now.Before(g.until) {
			// This route checks; the rest wait for its answer.
			step := g.every
			if step == 0 {
				step = offlineWait
			}
			g.until = now.Add(step)
			g.probing = true
			g.mu.Unlock()
			return ctx.Err() == nil
		}
		ch, d := g.wake, g.until.Sub(now)
		g.mu.Unlock()
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return false
		case <-ch:
		case <-t.C:
		}
		t.Stop()
	}
}

// unreachable tells whether err means the device has no network at all.
func unreachable(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "network is unreachable") ||
		strings.Contains(m, "unreachable network") || // Windows: WSAENETUNREACH
		strings.Contains(m, "no route to host")
}

// logLimiter merges repeated log lines: of lines that differ only in
// numbers, logRepeat a minute are logged; the rest are counted, and the
// next one logged says how many were left out.
type logLimiter struct {
	mu   sync.Mutex
	seen map[string]*logSeen
}

type logSeen struct {
	start   time.Time
	n       int
	dropped int
}

const (
	logRepeat = 3
	logWindow = time.Minute
)

func (l *logLimiter) allow(line string, now time.Time) (string, bool) {
	key := logTemplate(line)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = map[string]*logSeen{}
	}
	s := l.seen[key]
	if s == nil || now.Sub(s.start) >= logWindow {
		if len(l.seen) > 256 {
			for k, o := range l.seen {
				if now.Sub(o.start) >= logWindow {
					delete(l.seen, k)
				}
			}
		}
		dropped := 0
		if s != nil {
			dropped = s.dropped
		}
		s = &logSeen{start: now}
		l.seen[key] = s
		if dropped > 0 {
			line = fmt.Sprintf("%s (and %d more like it)", line, dropped)
		}
	}
	s.n++
	if s.n > logRepeat {
		s.dropped++
		return "", false
	}
	return line, true
}

// logTemplate is a line with its numbers left out.
func logTemplate(line string) string {
	var b strings.Builder
	digit := false
	for _, r := range line {
		if r >= '0' && r <= '9' {
			if !digit {
				b.WriteByte('#')
			}
			digit = true
			continue
		}
		digit = false
		b.WriteRune(r)
	}
	return b.String()
}
