package split

import (
	"context"
	"net/netip"
	"os"
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
	// Addr is the tunnel's address (for DialVPN).
	Addr netip.Addr
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
	// socks: the route each program's UDP socket took (sockRoute), so
	// that all its later destinations take it too.
	socks map[netip.AddrPort]*sockRoute

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

	fmu    sync.Mutex
	failed map[string]*Failure // sites that did not open direct (retry.go)

	amu    sync.Mutex
	probes map[string]*appProbe // programs sent direct by their rule (appwatch.go)

	gmu  sync.Mutex
	game gameSeen // the game that ran last (anticheat.go)

	history map[histKey]*Conn // ended connections (history.go); under mu
}

// sockRoute: the route of a program's UDP socket. A game talks to its
// matchmaking, to the servers it measures and to the match from one
// socket, and the servers compare the address each of them saw: if one
// destination went direct and another through the VPN (the program looked
// up again, and Windows had given the port to another program meanwhile),
// they saw two addresses, and the match never started. So the socket
// keeps the program found for it, and the route its program's rule gave
// (byApp; a route by the destination, a site or an address list, is
// decided for each destination as before).
type sockRoute struct {
	d     Decision
	byApp bool
	proc  *Proc
	last  int64 // unix ns: last used
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
	// prelim: the route before the name is read.
	prelim Decision
	// retry: sent direct, it is tried through the VPN when it does not
	// open; viaVPN: it did not open direct lately, so it goes through the
	// VPN at once (a placeholder: through the router).
	retry  bool
	viaVPN bool
	// hidden: the router's own half of another connection (not listed).
	hidden bool
	// qwatch: a direct QUIC flow waiting for its first answer; qheld:
	// copies of its first packets (retry.go).
	qretry bool // QUIC that may be retried (set once, in newFlow)
	// reject: IPv6 for the VPN, which carries IPv4 only: TCP gets a reset
	// at once (the program falls back to IPv4), UDP is dropped.
	reject bool
	// byApp: sent direct by its program's own rule (appwatch.go); probe:
	// that program's watch (UDP).
	byApp  bool
	probe  *appProbe
	qwatch atomic.Bool
	qmu    sync.Mutex
	qheld  [][]byte
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
	r := &Router{inner: dev, o: o, mtu: mtu, flows: map[flowKey]*flow{}, frags: map[fragKey]*fragState{}, logged: map[string]bool{}, socks: map[netip.AddrPort]*sockRoute{},
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
	r.socks = map[netip.AddrPort]*sockRoute{}
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
	r.socks = map[netip.AddrPort]*sockRoute{}
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
// unreachable6 tells the program that sent a direct IPv6 datagram that
// its destination cannot be reached, so that it uses IPv4 at once.
func (r *Router) unreachable6(k flowKey, payload []byte) {
	inv := udpPackets(k.src, k.dst, payload, r.mtu, 0, 0)
	if len(inv) == 0 {
		return
	}
	r.writeOut([][]byte{icmp6Unreachable(k.dst.Addr(), k.src.Addr(), inv[0])}, 0)
}

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
		if f.reject {
			// IPv6 for the VPN: the program hears so and uses IPv4.
			if !p.frag || p.firstFrg {
				r.unreachable6(p.key, p.payload)
			}
			return false
		}
		if f.qwatch.Load() {
			f.quicKeepPkt(b)
		}
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
	// A UDP socket that a program's rule already routed (sockRoute); not
	// QUIC, whose route comes from the site's name.
	sockKeep := p.key.proto == protoUDP && !fixed && !fake && !p.frag && !sniffPort(protoUDP, p.key.dst.Port())
	var sticky *sockRoute
	if sockKeep {
		r.mu.Lock()
		if s := r.socks[p.key.src]; s != nil {
			s.last = now
			sticky = s
		}
		r.mu.Unlock()
	}
	// With the others direct, TurnVK's own checks (made through the
	// tunnel on purpose) have to be told apart too.
	if sticky != nil {
		proc = sticky.proc
	} else if r.o.Owner != nil && (!fixed && (m.needsProc() || m.anyDirect) || r.watching(now)) {
		proc = r.o.Owner.Lookup(p.key.proto, p.key.src, p.key.dst, m.kids)
	}
	switch {
	case fixed:
	case sticky != nil && sticky.byApp:
		d = sticky.d
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
		}
	}
	// An anti-cheat service goes where the game goes; a game's route is
	// noted for it (anticheat.go).
	if proc != nil && proc.Path != "" && !fixed && !fake && proc.PID != r.self {
		a, parent := m.appFor(proc)
		switch {
		case a == nil && isAntiCheat(proc.Path):
			if g, ok := r.lastGame(now); ok {
				d = Decision{g.route, whyAntiCheat + g.name}
			}
		case isGameRule(a, parent) && (d == Decision{a.Route, m.why(a, parent)} || d.Why == whyAppFailed):
			r.noteGame(proc.Path, d.Route, now)
		}
	}
	// Sent direct by the program's own rule (a game): watched as a whole,
	// and through the VPN while it fails direct (appwatch.go).
	if d.Route == Direct && proc != nil && proc.Path != "" && !fixed && !fake {
		if a, parent := m.appFor(proc); a != nil && d == (Decision{a.Route, m.why(a, parent)}) {
			if r.appFailed(proc.Path) {
				d = Decision{VPN, whyAppFailed}
			} else {
				f.byApp = true
				if p.key.proto == protoUDP {
					f.probe = r.probeFor(proc.Path, now)
				}
			}
		}
	}
	// A site sent direct is accepted here, to be tried through the VPN if
	// it does not open (not the local network).
	f.retry = m.retry && p.key.proto == protoTCP && sniffPort(protoTCP, p.key.dst.Port()) && !p.frag && (!fixed || fake)
	if f.retry && d.Route == Direct {
		f.sniffing = true
		if r.failedBefore(f.host, dst) {
			f.viaVPN = true
			if !fake {
				d = Decision{VPN, whyFailed}
				f.sniffing = f.host == "" && m.sniffable(VPN)
			}
		}
	}
	// QUIC sent direct: through the VPN if it did not answer lately.
	quic := m.retry && p.key.proto == protoUDP && sniffPort(protoUDP, p.key.dst.Port()) && !p.frag && !fixed && !fake
	f.qretry = quic
	if quic && d.Route == Direct && !f.sniffing && r.failedBeforeQUIC(f.host, dst) {
		d = Decision{VPN, whyFailed}
		f.viaVPN = true
	}
	if p.v6 {
		// IPv6 goes direct only: nothing is relayed or retried through
		// the VPN, which carries IPv4.
		f.sniffing, f.quic, f.retry, f.qretry = false, nil, false, false
		if d.Route == VPN {
			f.reject = true
			d.Why += " (IPv6 — только напрямую, программа перейдёт на IPv4)"
		}
	}
	if f.sniffing {
		// Relaying into the VPN needs the pump: start it now, while the
		// computer still sends (the next Read starts it).
		r.wantPump.Store(true)
	}
	f.prelim = d
	f.route, f.why = d.Route, d.Why
	f.proc = proc
	f.local.Store(d.Route == Direct || f.sniffing || f.reject)
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
	if sockKeep && sticky == nil && proc != nil && proc.PID != r.self && len(r.socks) < maxFlows {
		a, parent := m.appFor(proc)
		byApp := a != nil && d == Decision{a.Route, m.why(a, parent)}
		r.socks[p.key.src] = &sockRoute{d: d, byApp: byApp, proc: proc, last: now}
	}
	if len(r.flows) >= maxFlows {
		r.evictLocked()
	}
	r.flows[p.key] = f
	if f.quic != nil {
		r.quicTimer(f)
	}
	if f.qretry && f.route == Direct && !f.sniffing {
		r.quicWatch(f)
	}
	if f.local.Load() {
		f.counted = true
		r.direct.Add(1)
	}
	if f.route == Direct && !f.sniffing {
		name := baseName(f.path)
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
	r.noteHistoryLocked(k, f)
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
		r.expireProbes(now)
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
		for k, s := range r.socks {
			if now.Sub(time.Unix(0, s.last)) > natIdle {
				delete(r.socks, k)
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
	// Site: the rule a site would get (its main domain: googlevideo.com
	// for rr3---sn-x.googlevideo.com).
	Site string `json:"site,omitempty"`
	// Retried: it did not open direct, so it went through the VPN.
	Retried bool `json:"retried,omitempty"`
	// N: how many such connections (History merges them).
	N int `json:"n,omitempty"`
}

// DirectStats: the direct path's numbers for the statistics.
type DirectStats struct {
	Flows    int    // open direct flows
	UDPSocks int    // direct UDP sockets open
	UDPErr   uint64 // direct UDP sends that failed, since the start
}

// Stats returns the direct path's numbers.
func (r *Router) Stats() DirectStats {
	return DirectStats{Flows: int(r.direct.Load()), UDPSocks: r.udp.count(), UDPErr: r.udp.sendErr.Load()}
}

// Conns lists the known connections, most recently active first (at most
// limit).
func (r *Router) Conns(limit int) []Conn {
	r.mu.Lock()
	out := make([]Conn, 0, len(r.flows))
	for k, f := range r.flows {
		if f.hidden {
			continue
		}
		out = append(out, r.connOf(k, f))
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Last > out[j].Last })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
