package split

import (
	"sort"
	"time"
)

// Recent history: connections that have ended stay listed for a while,
// merged by program, site and route, so that what a game connected to can
// be seen after it was closed.

const (
	maxHistory = 400
	historyFor = time.Hour
)

type histKey struct {
	path, site string
	route      Route
	proto      uint8
}

// noteHistoryLocked keeps an ended flow; r.mu is held.
func (r *Router) noteHistoryLocked(k flowKey, f *flow) {
	if f.hidden || f.sniffing || f.up.Load() == 0 {
		return
	}
	c := r.connOf(k, f)
	c.Closed = true
	site := c.Host
	if site == "" {
		site = k.dst.Addr().String()
	}
	hk := histKey{path: f.path, site: site, route: f.route, proto: uint8(k.proto)}
	if r.history == nil {
		r.history = map[histKey]*Conn{}
	}
	if h := r.history[hk]; h != nil {
		h.N++
		h.Up += c.Up
		h.Down += c.Down
		h.Start = min(h.Start, c.Start)
		if c.Last > h.Last {
			h.Last, h.Dst, h.Src, h.Why, h.PID = c.Last, c.Dst, c.Src, c.Why, c.PID
		}
		return
	}
	c.N = 1
	if len(r.history) >= maxHistory {
		r.trimHistoryLocked(time.Now())
	}
	r.history[hk] = &c
}

// trimHistoryLocked drops what is too old, then the oldest quarter if
// still full.
func (r *Router) trimHistoryLocked(now time.Time) {
	cut := now.Add(-historyFor).UnixMilli()
	for k, h := range r.history {
		if h.Last < cut {
			delete(r.history, k)
		}
	}
	if len(r.history) < maxHistory {
		return
	}
	type kv struct {
		k histKey
		l int64
	}
	all := make([]kv, 0, len(r.history))
	for k, h := range r.history {
		all = append(all, kv{k, h.Last})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].l < all[j].l })
	for _, e := range all[:len(all)/4] {
		delete(r.history, e.k)
	}
}

// History lists the connections that ended in the last hour, merged by
// program, site and route (N: how many), most recent first.
func (r *Router) History(limit int) []Conn {
	r.mu.Lock()
	r.trimHistoryLocked(time.Now())
	out := make([]Conn, 0, len(r.history))
	for _, h := range r.history {
		out = append(out, *h)
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Last > out[j].Last })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ForgetHistory empties the history.
func (r *Router) ForgetHistory() {
	r.mu.Lock()
	r.history = nil
	r.mu.Unlock()
}

// connOf describes a flow for the app; r.mu is held.
func (r *Router) connOf(k flowKey, f *flow) Conn {
	c := Conn{Proto: "TCP", Src: k.src.String(), Dst: k.dst.String(), PID: f.pid, Path: f.path, Route: f.route, Why: f.why,
		Host: f.host, Up: f.up.Load(), Down: f.down.Load(), Start: f.start.UnixMilli(), Last: f.last.Load() / 1e6, Closed: f.closed.Load()}
	if k.proto == protoUDP {
		c.Proto = "UDP"
	}
	if f.path != "" {
		c.Name = baseName(f.path)
	}
	if f.host != "" {
		c.Site = siteRule(f.host)
	}
	c.Retried = f.why == whyRetried || f.why == whyFailed
	return c
}
