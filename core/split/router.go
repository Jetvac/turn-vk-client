package split

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// Options configure a Router.
type Options struct {
	// Protect binds a socket to the physical network (Windows: the
	// VPN's Protect). Direct connections are opened through such sockets.
	Protect func(fd uintptr) error
	// Owner finds the program behind a connection (nil: unknown).
	Owner Owner
	// AlwaysVPN: the tunnel's own network and its DNS servers, which only
	// the VPN can reach.
	AlwaysVPN []netip.Prefix
	// DNS: the tunnel's DNS servers (their encrypted DNS is refused while
	// sites go direct by name).
	DNS []netip.Addr
	// Fake hands out placeholder addresses for sites sent direct (nil: no
	// rules by name).
	Fake *Fake
	// Resolver resolves sites sent direct on the physical network.
	Resolver interface {
		LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	}
	// Self is TurnVK's own ID as Owner reports it (0: this process's ID);
	// its connections go through the VPN.
	Self uint32
	// Lists: the lists loaded when connecting (SetLists changes them).
	Lists *Lists
	Logf  func(string, ...any)

	// remap changes where direct connections really go (tests: the
	// simulated computer cannot address loopback).
	remap func(netip.AddrPort) netip.AddrPort
}

const (
	udpIdle    = 2 * time.Minute
	tcpIdle    = 15 * time.Minute
	closedIdle = 30 * time.Second
	maxFlows   = 65536
	// watchFor: how long the connection list keeps being filled after the
	// page last asked for it (with the rules off, programs are looked up
	// only while someone looks).
	watchFor = 15 * time.Second
)

// Router is a tun.Device between the adapter and WireGuard. Reads (the
// computer's outgoing packets) are sorted: the VPN's go on to WireGuard,
// direct ones are taken out and sent on the physical network. Writes
// (WireGuard's packets for the computer) pass through.
type Router struct {
	inner  tun.Device
	o      Options
	mtu    int
	ctx    context.Context
	cancel context.CancelFunc

	m     atomic.Pointer[matcher]
	self  uint32
	smu   sync.Mutex // rules and lists, for building m
	rules Rules
	lists *Lists
	watch atomic.Int64 // unix ns until which flows are tracked with the rules off

	mu    sync.Mutex
	flows map[flowKey]*flow
	frags map[fragKey]*fragState
	// direct: open direct flows; with none and the rules off, packets
	// pass untouched.
	direct atomic.Int32
	logged map[string]bool

	hmu   sync.Mutex
	hosts map[netip.Addr]hostEntry // real address -> name, from DNS answers

	rmu      sync.Mutex
	resolved map[string]resolved

	wmu   sync.Mutex // writes to the adapter
	tcp   *tcpDirect
	tcpMu sync.Mutex
	udp   *udpNAT

	// The router's own packets for WireGuard (connections it relays into
	// the VPN once it has read the site's name): once one may be needed,
	// the adapter is read by a goroutine (pump), so that Read can return
	// these too instead of waiting on the adapter.
	injectQ  chan []byte
	wantPump atomic.Bool
	pumping  bool // Read's goroutine only
	pumpCh   chan *pumpBatch
	relay    *vpnRelay
	relayMu  sync.Mutex
	relayN   atomic.Int32 // open relayed connections
}

type flow struct {
	key     flowKey
	route   Route
	why     string
	pid     uint32
	path    string
	host    string // the site's name, when known
	start   time.Time
	last    atomic.Int64 // unix ns
	up      atomic.Uint64
	down    atomic.Uint64
	closed  atomic.Bool // TCP: FIN or RST seen, or the direct connection ended
	counted bool        // counted in Router.direct
	// local: the packets are handled here (direct, relayed into the VPN
	// after reading the site's name, or waiting for that name), not
	// passed to WireGuard as they are.
	local atomic.Bool
	// sniffing: the route waits for the site's name from the connection
	// itself (TLS, HTTP, QUIC); quic holds the waiting QUIC packets.
	sniffing bool
	quic     *quicSniff
	relayed  atomic.Bool // TCP relayed into the VPN by the router
	proc     *Proc
}

func (f *flow) touch(now int64) { f.last.Store(now) }

// New wraps the adapter dev.
func New(dev tun.Device, o Options, rules Rules) *Router {
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	mtu, err := dev.MTU()
	if err != nil || mtu < 576 {
		mtu = 1280
	}
	r := &Router{inner: dev, o: o, mtu: mtu, flows: map[flowKey]*flow{}, frags: map[fragKey]*fragState{}, logged: map[string]bool{},
		hosts: map[netip.Addr]hostEntry{}, resolved: map[string]resolved{}}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	r.injectQ = make(chan []byte, 1024)
	r.pumpCh = make(chan *pumpBatch)
	r.udp = newUDPNAT(r)
	r.lists = o.Lists
	r.self = o.Self
	if r.self == 0 {
		r.self = uint32(os.Getpid())
	}
	r.SetRules(rules)
	go r.expire()
	return r
}

// SetRules applies new rules to new connections; open ones keep their
// route.
func (r *Router) SetRules(rules Rules) {
	r.smu.Lock()
	r.rules = rules
	r.m.Store(newMatcher(rules, r.o.AlwaysVPN, r.lists))
	r.smu.Unlock()
	r.mu.Lock()
	r.logged = map[string]bool{}
	r.mu.Unlock()
}

// SetLists gives the router newly loaded lists (nil: none).
func (r *Router) SetLists(l *Lists) {
	r.smu.Lock()
	r.lists = l
	r.m.Store(newMatcher(r.rules, r.o.AlwaysVPN, l))
	r.smu.Unlock()
	r.mu.Lock()
	r.logged = map[string]bool{}
	r.mu.Unlock()
}

// Watch keeps the connection list filling for a while, rules on or off.
func (r *Router) Watch() { r.watch.Store(time.Now().Add(watchFor).UnixNano()) }

func (r *Router) watching(now int64) bool { return now < r.watch.Load() }

// --- tun.Device ---

func (r *Router) File() *os.File           { return r.inner.File() }
func (r *Router) MTU() (int, error)        { return r.inner.MTU() }
func (r *Router) Name() (string, error)    { return r.inner.Name() }
func (r *Router) Events() <-chan tun.Event { return r.inner.Events() }
func (r *Router) BatchSize() int           { return r.inner.BatchSize() }

func (r *Router) Close() error {
	r.cancel()
	r.tcpMu.Lock()
	if r.tcp != nil {
		r.tcp.close()
	}
	r.tcpMu.Unlock()
	r.relayMu.Lock()
	if r.relay != nil {
		r.relay.close()
	}
	r.relayMu.Unlock()
	r.udp.close()
	return r.inner.Close()
}

func (r *Router) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		if !r.pumping && r.wantPump.Load() {
			// Not inside the adapter's Read now: the pump takes over.
			r.pumping = true
			go r.pump(len(bufs), len(bufs[0]), offset)
		}
		var n int
		var err error
		if r.pumping {
			var own bool
			n, own, err = r.readPumped(bufs, sizes, offset)
			if own {
				return n, nil // the router's own packets, routed already
			}
		} else {
			n, err = r.inner.Read(bufs, sizes, offset)
		}
		if n == 0 {
			return n, err
		}
		m := r.m.Load()
		now := time.Now().UnixNano()
		if !m.rules.On && r.direct.Load() == 0 && !r.watching(now) {
			return n, err
		}
		k := 0
		for i := 0; i < n; i++ {
			b := bufs[i][offset : offset+sizes[i]]
			if r.route(b, m, now) {
				if k != i {
					copy(bufs[k][offset:], b)
					sizes[k] = sizes[i]
				}
				k++
			}
		}
		if k > 0 || err != nil {
			return k, err
		}
	}
}

func (r *Router) Write(bufs [][]byte, offset int) (int, error) {
	all := len(bufs)
	if r.m.Load().rules.On || r.watching(time.Now().UnixNano()) || r.relayN.Load() > 0 {
		var p pkt
		var keep [][]byte
		for i, b := range bufs {
			// Replies: the program is the destination.
			if parse(b[offset:], &p) && !p.frag {
				if p.key.proto == protoUDP && p.key.src.Port() == 53 {
					r.dnsSnoop(p.payload)
				}
				r.mu.Lock()
				f := r.flows[flowKey{p.key.proto, p.key.dst, p.key.src}]
				r.mu.Unlock()
				if f != nil && f.relayed.Load() {
					// The far end of a connection the router relays: for
					// the router's own TCP stack, not the computer.
					if keep == nil {
						keep = append(make([][]byte, 0, len(bufs)), bufs[:i]...)
					}
					if rl := r.vpnRelay(); rl != nil {
						rl.inject(b[offset:])
					}
					continue
				}
				if f != nil {
					f.down.Add(uint64(len(b) - offset))
				}
			}
			if keep != nil {
				keep = append(keep, b)
			}
		}
		if keep != nil {
			bufs = keep
		}
	}
	if len(bufs) == 0 {
		return all, nil
	}
	r.wmu.Lock()
	defer r.wmu.Unlock()
	if _, err := r.inner.Write(bufs, offset); err != nil {
		return 0, err
	}
	return all, nil
}

// writeOut sends packets of direct connections to the computer.
func (r *Router) writeOut(pkts [][]byte, offset int) {
	r.wmu.Lock()
	_, err := r.inner.Write(pkts, offset)
	r.wmu.Unlock()
	if err != nil && r.ctx.Err() == nil {
		r.o.Logf("split: writing to the adapter: %v", err)
	}
}

// route handles one outgoing packet; true sends it to the VPN.
func (r *Router) route(b []byte, m *matcher, now int64) bool {
	var p pkt
	if !parse(b, &p) {
		return true
	}
	if p.frag && !p.firstFrg {
		return !r.fragment(b, &p)
	}
	if m.byName {
		if p.key.proto == protoUDP && p.key.dst.Port() == 53 && !p.frag && r.dnsQuery(&p, m) {
			return false
		}
		if m.directSites && r.blockDoH(b, &p) {
			return false
		}
	}
	r.mu.Lock()
	f := r.flows[p.key]
	r.mu.Unlock()
	if f == nil {
		if p.key.proto == protoTCP && !p.syn {
			// A connection from before the rules (or from before this
			// list was kept): it goes where it always went.
			return true
		}
		f = r.newFlow(&p, m, now)
	}
	f.touch(now)
	f.up.Add(uint64(len(b)))
	if p.fin || p.rst {
		f.closed.Store(true)
	}
	if f.quic != nil && r.quicHold(f, b, &p) {
		return false
	}
	if !f.local.Load() {
		return true
	}
	switch p.key.proto {
	case protoTCP:
		if t := r.tcpStack(); t != nil {
			t.inject(b)
		}
	case protoUDP:
		if p.firstFrg {
			r.startFragments(b, &p, f)
		} else {
			r.udp.send(f, p.payload)
		}
	}
	return false
}

func (r *Router) newFlow(p *pkt, m *matcher, now int64) *flow {
	f := &flow{key: p.key, start: time.Unix(0, now)}
	dst := p.key.dst.Addr()
	fake := isFake(dst)
	if fake {
		f.host = r.o.Fake.Name(dst)
	} else {
		f.host = r.hostOf(dst)
	}
	d, fixed := m.fixed(dst)
	if fake {
		// A placeholder is a site sent direct; it stays direct even if
		// the rule changed since (the program asks again within a second).
		d, fixed = Decision{Direct, "сайт " + f.host}, true
		if f.host == "" {
			d.Why = "устаревший адрес-заменитель"
		} else if sd, ok := m.site(f.host); ok && sd.Route == Direct {
			d.Why = sd.Why
		}
	}
	var proc *Proc
	// With the others direct, TurnVK's own checks (made through the
	// tunnel on purpose) have to be told apart too.
	if r.o.Owner != nil && (!fixed && (m.needsProc() || m.anyDirect) || r.watching(now)) {
		proc = r.o.Owner.Lookup(p.key.proto, p.key.src, p.key.dst, m.kids)
	}
	switch {
	case fixed:
	case proc != nil && proc.PID == r.self:
		d = Decision{VPN, "проверка TurnVK"}
	default:
		d = m.decide(dst, f.host, proc)
		// The site is not known by name (its program resolved it some
		// other way: its own encrypted DNS, Android's private DNS, an
		// address of its own) and a rule for sites could change the
		// route: the name is read from the connection's first bytes.
		if f.host == "" && m.sniffable(d.Route) && sniffPort(p.key.proto, p.key.dst.Port()) && !p.frag {
			f.sniffing = true
			if p.key.proto == protoUDP {
				f.quic = &quicSniff{prelim: d}
			}
			// Relaying into the VPN needs the pump: start it now, while
			// the computer still sends (the next Read starts it).
			r.wantPump.Store(true)
		}
	}
	f.route, f.why = d.Route, d.Why
	f.proc = proc
	f.local.Store(d.Route == Direct || f.sniffing)
	if f.sniffing {
		f.why = "узнаю сайт"
	}
	if proc != nil {
		f.pid, f.path = proc.PID, proc.Path
	}
	f.touch(now)
	r.mu.Lock()
	if old := r.flows[p.key]; old != nil {
		r.mu.Unlock()
		return old
	}
	if len(r.flows) >= maxFlows {
		r.evictLocked()
	}
	r.flows[p.key] = f
	if f.quic != nil {
		r.quicTimer(f)
	}
	if f.local.Load() {
		f.counted = true
		r.direct.Add(1)
	}
	if f.route == Direct && !f.sniffing {
		name := filepath.Base(f.path)
		if f.path == "" {
			name = "?"
		}
		if lk := name + "|" + f.why; !r.logged[lk] && len(r.logged) < 200 {
			r.logged[lk] = true
			r.mu.Unlock()
			r.o.Logf("split: %s goes direct (%s)", name, f.why)
			return f
		}
	}
	r.mu.Unlock()
	return f
}

// dropFlow forgets a flow; r.mu is held.
func (r *Router) dropLocked(k flowKey, f *flow) {
	delete(r.flows, k)
	if f.counted {
		r.direct.Add(-1)
	}
}

// evictLocked makes room by dropping the oldest idle flows.
func (r *Router) evictLocked() {
	type kv struct {
		k flowKey
		f *flow
	}
	all := make([]kv, 0, len(r.flows))
	for k, f := range r.flows {
		all = append(all, kv{k, f})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].f.last.Load() < all[j].f.last.Load() })
	for _, e := range all[:len(all)/4] {
		r.dropLocked(e.k, e.f)
	}
}

func (r *Router) expire() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		r.expireHosts(now)
		r.mu.Lock()
		for k, f := range r.flows {
			idle := now.Sub(time.Unix(0, f.last.Load()))
			limit := udpIdle
			if k.proto == protoTCP {
				limit = tcpIdle
				if f.local.Load() && !f.closed.Load() {
					continue // ends with its connection
				}
			}
			if f.closed.Load() {
				limit = closedIdle
			}
			if idle > limit {
				r.dropLocked(k, f)
			}
		}
		for k, s := range r.frags {
			if now.Sub(s.start) > 5*time.Second {
				delete(r.frags, k)
			}
		}
		r.mu.Unlock()
	}
}

// tcpStack starts the TCP stack for direct connections on first use.
func (r *Router) tcpStack() *tcpDirect {
	r.tcpMu.Lock()
	defer r.tcpMu.Unlock()
	if r.tcp == nil && r.ctx.Err() == nil {
		t, err := newTCPDirect(r)
		if err != nil {
			r.o.Logf("split: TCP stack: %v", err)
			return nil
		}
		r.tcp = t
	}
	return r.tcp
}

func (r *Router) flowFor(k flowKey) *flow {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.flows[k]
}

// --- the connection list ---

// Conn is a connection as the app shows it.
type Conn struct {
	Proto  string `json:"proto"`
	Src    string `json:"src"`
	Dst    string `json:"dst"`
	PID    uint32 `json:"pid,omitempty"`
	Path   string `json:"path,omitempty"`
	Name   string `json:"name,omitempty"`
	Host   string `json:"host,omitempty"` // the site's name
	Route  Route  `json:"route"`
	Why    string `json:"why"`
	Up     uint64 `json:"up"`
	Down   uint64 `json:"down"`
	Start  int64  `json:"start"` // unix ms
	Last   int64  `json:"last"`  // unix ms
	Closed bool   `json:"closed,omitempty"`
}

// Conns lists the known connections, most recently active first (at most
// limit).
func (r *Router) Conns(limit int) []Conn {
	r.mu.Lock()
	out := make([]Conn, 0, len(r.flows))
	for k, f := range r.flows {
		c := Conn{Proto: "TCP", Src: k.src.String(), Dst: k.dst.String(), PID: f.pid, Path: f.path, Route: f.route, Why: f.why,
			Host: f.host, Up: f.up.Load(), Down: f.down.Load(), Start: f.start.UnixMilli(), Last: f.last.Load() / 1e6, Closed: f.closed.Load()}
		if k.proto == protoUDP {
			c.Proto = "UDP"
		}
		if f.path != "" {
			c.Name = filepath.Base(f.path)
		}
		out = append(out, c)
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Last > out[j].Last })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
