// Package engine runs the client: it keeps a pool of transport sessions to
// a WDTT server (each through its own VK TURN allocation), feeds them from
// an in-process WireGuard device and reconnects whatever fails.
package engine

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/Jetvac/turn-vk-client/core/link"
	"github.com/Jetvac/turn-vk-client/core/netx"
	"github.com/Jetvac/turn-vk-client/core/session"
	"github.com/Jetvac/turn-vk-client/core/vkcreds"
	"github.com/Jetvac/turn-vk-client/core/wrap"
)

// Config of a connection.
type Config struct {
	Link     link.Link
	DeviceID string
	// Sessions is the number of parallel transport sessions (TURN
	// allocations). More sessions give more throughput and resilience.
	Sessions   int
	Mode       wrap.Mode
	TURNServer string // host:port, overrides the servers VK returns
	Net        *netx.Net
	Captcha    vkcreds.CaptchaSolver
	// VKCache is the file that keeps VK guest tokens between runs, so that
	// a restart does not bring up a captcha ("" keeps them in memory).
	VKCache string
	// NoRelayScoring keeps the plain rotation over VK's TURN servers
	// (for comparisons; see relays.go).
	NoRelayScoring bool
	Logf           func(format string, args ...any)
	// NoStats: send the server no statistics (stats.go). Client names the
	// app for them, e.g. "TurnVK 0.5.0 windows".
	NoStats bool
	Client  string
	// OnStatus is called (from any goroutine) when the status changes.
	OnStatus func(Status)
	// Power: the power mode (phones, idle.go). PowerBalanced and PowerSaver
	// turn on idle mode: an idle tunnel keeps a few routes, which ping
	// together, so that the radio can sleep; PowerSaver idles sooner, on
	// fewer routes. PowerAlways and "" (desktops) never idle.
	Power string
	// Device, when set, reports the battery and power state for the
	// statistics (device.go); called once a minute.
	Device func() *DeviceState
	// Network, when set, reports the physical network for the statistics
	// (netstate.go); called once a minute.
	Network func() *NetState
	// Direct, when set, reports the split tunneling's direct path for the
	// statistics (stats.go); called once a minute.
	Direct func() DirectState
}

// DirectState: the direct path of split tunneling (split.Router.Stats).
type DirectState struct {
	Flows    int    // open direct flows
	UDPSocks int    // direct UDP sockets open
	UDPErr   uint64 // direct UDP sends that failed, since the start
}

// TunFactory creates the tunnel interface once the server's WireGuard
// config is known (address, DNS, MTU).
type TunFactory func(*WGConfig) (tun.Device, error)

// State of the engine.
const (
	StateConnecting = "connecting"
	StateConnected  = "connected"
	StateCaptcha    = "captcha"
	StateFailed     = "failed"
	StateStopped    = "stopped"
)

// Status is a snapshot for the UI.
type Status struct {
	State      string `json:"state"`
	Sessions   int    `json:"sessions"`
	Target     int    `json:"target"`
	Address    string `json:"address,omitempty"`
	RxBytes    uint64 `json:"rx_bytes"`
	TxBytes    uint64 `json:"tx_bytes"`
	Reconnects uint64 `json:"reconnects"`
	LastError  string `json:"last_error,omitempty"`
	Since      int64  `json:"since"`
	// Protocol is "direct" (TurnVK server) or "dtls" (standard server).
	Protocol string `json:"protocol,omitempty"`
	// Quiet: the tunnel is idle and keeps a few routes (idle.go).
	Quiet bool `json:"quiet,omitempty"`
	RTT   int  `json:"rtt_ms,omitempty"` // average over the paths
	// Captcha: VK is waiting for the user to pass its check. The state
	// shows it only while there is no working session; a connection
	// that works meanwhile stays "connected".
	Captcha bool `json:"captcha,omitempty"`
	// Paths lists the open sessions (routes through VK TURN).
	Paths []PathStatus `json:"paths,omitempty"`
}

// PathStatus is one session in the status.
type PathStatus struct {
	ID     int    `json:"id"`
	Server string `json:"server"`           // VK TURN server
	RTT    int    `json:"rtt_ms,omitempty"` // last measured round trip
	Fresh  bool   `json:"fresh"`            // heard from recently
	Rx     uint64 `json:"rx"`
	Tx     uint64 `json:"tx"`
	// RxPackets and Lost: the server's packets received and lost on the
	// way (direct protocol).
	RxPackets uint64 `json:"rx_packets"`
	Lost      uint64 `json:"lost"`
	// Upload pacing (once the server sends FEEDBACK): rate in bytes/s,
	// loss the server reports, queue delay over the path's base.
	UpRate  int     `json:"up_rate,omitempty"`
	UpLoss  float64 `json:"up_loss,omitempty"`
	UpQueue int     `json:"up_queue_ms,omitempty"`
}

const (
	defaultSessions = 16
	maxSessions     = 64
	setupTimeout    = 45 * time.Second
	firstWait       = 2 * time.Minute // longest wait for VK before the first session
	staleRx         = 180 * time.Second
	silentActive    = 8 * time.Second
	silentProbe     = 2 * time.Second // direct protocol: probe the paths
	// pathReplace: a direct path silent this long while others answer is
	// replaced (three missed pings).
	pathReplace = 6 * time.Second
	// relayDownProof: how much later than a silent TURN server's routes
	// others must have answered for that server to be blamed (a ping
	// round, so a server restart or lost network blames no relay).
	relayDownProof = 2 * time.Second
	// wakeGrace: after the device slept, routes get this long to answer
	// before any is replaced; sleepGap: a gap between the watchdog's ticks
	// (wall clock) this long means the device slept.
	wakeGrace = 15 * time.Second
	sleepGap  = 4 * time.Second
	// sleepCheck: only a sleep this long gets every route probed (and a
	// line in the log). Android pauses an app with the screen off for a
	// few seconds at a time, over and over: those short pauses only hold
	// off route replacement.
	sleepCheck = 20 * time.Second
	// dozeWindow: for this long after the device last slept it counts as
	// dozing, and a direct path is replaced only after dozeReplace of
	// silence (its pings were paused too).
	dozeWindow  = 2 * time.Minute
	dozeReplace = 20 * time.Second
	// relayMoveEvery: at most one route moves to a better relay this often.
	relayMoveEvery = 30 * time.Second
	// VK's allocation limit (error 486) with no guest to move to: the
	// group waits quotaWait (doubling up to quotaWaitMax) and the engine
	// uses fewer routes (targetStep less, down to half) for a while; after
	// targetRestore without error 486 it tries targetStep more again.
	quotaWait     = time.Minute
	quotaWaitMax  = 5 * time.Minute
	quotaCalm     = 3 * time.Minute // no route moves this long after error 486
	targetStep    = 8
	targetRestore = 15 * time.Minute
	// offlineWait: with no network (sendto: network is unreachable) new
	// routes wait this long, or until the platform reports a new network.
	offlineWait = 15 * time.Second
	// silentWait..silentWaitMax: while the WDTT server answers no route
	// (it is down, or its network is), one route checks it this often,
	// doubling; the rest wait. Each check costs a VK allocation.
	silentWait    = 15 * time.Second
	silentWaitMax = 2 * time.Minute
	// allocLife: how long VK may go on counting an allocation nobody
	// freed (a TURN allocation's lifetime).
	allocLife = 10 * time.Minute
	// raiseProbe: error 486 this soon after more routes were tried means
	// that number does not fit; the next try waits twice as long (up to
	// four times targetRestore).
	raiseProbe = 5 * time.Minute
)

// Engine is one running connection.
type Engine struct {
	cfg  Config
	aead cipher.AEAD
	vk   *vkcreds.Client
	peer *net.UDPAddr
	gen  string
	ctx  context.Context
	stop context.CancelFunc
	b    *bind
	dev  *device.Device
	wg   *WGConfig

	hashes  []*hashState
	workers sync.WaitGroup

	mu        sync.Mutex
	state     string
	lastErr   string
	since     time.Time
	fatal     error
	done      chan struct{}
	doneOnce  sync.Once
	rxClosed  atomic.Uint64
	txClosed  atomic.Uint64
	reconnect atomic.Uint64
	wakes     atomic.Uint64 // the device woke from sleep (watchdog)
	netChg    atomic.Uint64 // the network changed (Reconnect, SwitchNetwork)
	// network.go: the platform reports no network (netLost, since
	// netLostAt); heldAt: "routes kept" last logged.
	netLost atomic.Bool
	// relayprobe.go: relays being probed.
	probeMu      sync.Mutex
	relayProbing map[string]bool
	netLostAt    atomic.Int64
	heldAt       atomic.Int64
	captchas     atomic.Int32

	hadSessions atomic.Bool
	learned     session.LearnedRates // upload rates per TURN server
	relays      relays               // loss per TURN server
	rekeying    atomic.Bool
	lastReset   atomic.Int64

	// keys is this connection's own WireGuard key pair (direct protocol:
	// the server never sees the private key). mode is modeUnknown until
	// the first session shows whether the server speaks the direct
	// protocol; a link with the server's key always uses it.
	keys    session.Keys
	mode    atomic.Int32
	probing atomic.Bool

	diag diagState // for Diag: handshakes and traffic samples

	// wokeAt: when the device last woke from sleep (unix ns, wall clock);
	// massSilentLog: when "many routes silent" was last logged.
	wokeAt        atomic.Int64
	massSilentLog atomic.Int64

	// target: how many routes the engine keeps now (cfg.Sessions, less
	// while VK refuses allocations); quotaAt/targetAt: when error 486
	// last came and when target last changed (unix ns); movedAt: when a
	// route last moved to a better relay.
	target   atomic.Int32
	quotaAt  atomic.Int64
	targetAt atomic.Int64
	movedAt  atomic.Int64

	// offline: no network; new routes wait for it (offline.go).
	offline offlineGate
	// silent: the WDTT server answers no route; new routes wait (one
	// checks it now and then).
	silent offlineGate
	// raisedAt: when more routes were last tried (unix ns, 0 once
	// judged); raiseFails: how many tries in a row met error 486 at once.
	raisedAt   atomic.Int64
	raiseFails atomic.Int32
	// unfreedAt: when a route's allocation was last left unfreed.
	unfreedAt atomic.Int64
	// rtts: the round trips the routes' pings measured (statistics).
	rtts session.Hist

	logs logLimiter // merges repeated log lines

	statsAcked atomic.Bool // the server acknowledged a statistics report

	// quiet: idle mode (nil without Config.Quiet), idle.go.
	quiet *session.Quiet
	idle  idleState
}

const (
	modeUnknown int32 = iota
	modeDirect
	modeDTLS
)

// rehandshake drops WireGuard's current keys and starts a new handshake.
func (e *Engine) rehandshake(why string) {
	if e.dev == nil || e.ctx.Err() != nil || !e.rekeying.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer e.rekeying.Store(false)
		e.logf("new WireGuard handshake (%s)", why)
		// Down flushes the peer's keys; Up starts it again and, with a
		// persistent keepalive set, sends a handshake initiation at once.
		// A server that is still starting may miss it, so repeat every
		// second until something comes back (WireGuard itself would wait 5 s).
		for try := 0; try < 10 && e.ctx.Err() == nil; try++ {
			rx := e.b.rx.Load()
			_ = e.dev.Down()
			if e.ctx.Err() != nil {
				return
			}
			_ = e.dev.Up()
			for wait := 0; wait < 10; wait++ {
				if !sleep(e.ctx, 100*time.Millisecond) {
					return
				}
				if e.b.rx.Load() != rx {
					return
				}
			}
		}
	}()
}

// hashState is one VK call. Its sessions are split into groups of
// perCreds, each with credentials of its own: VK limits the allocations
// one set of credentials may hold.
type hashState struct {
	hash  string
	cache *vkcreds.Cache // saved credentials of the groups

	mu        sync.Mutex
	dead      error
	waitUntil time.Time
	groups    map[int]*credSlot
	full      map[int32]time.Time // guests that hit VK's allocation limit, when
	// start: when this engine began; bases: guests 0..bases-1 are the
	// groups' own; moved: a base guest an earlier run left busy -> the
	// guest its groups use instead (startGuest).
	start time.Time
	bases int32
	moved map[int32]int32
}

type credSlot struct {
	mu    sync.Mutex // held while fetching
	cur   atomic.Pointer[vkcreds.Creds]
	bg    atomic.Bool  // a background refresh is running
	guest atomic.Int32 // which guest of the call fetches for this group
	// quotaUntil: VK refused this group more allocations and no other
	// guest was free: no new route before then (unix ns); quotaFails: how
	// many times in a row.
	quotaUntil atomic.Int64
	quotaFails atomic.Int32
}

const (
	perCreds = 8
	// perGuest is how many sessions share one VK guest. VK refuses more
	// allocations than about 16–20 per guest (error 486), and each new
	// guest may cost a captcha: two groups per guest.
	perGuest  = 16
	maxGuests = 8
)

// New prepares an engine; Start connects.
func New(cfg Config) (*Engine, error) {
	if cfg.Sessions <= 0 {
		cfg.Sessions = defaultSessions
	}
	if cfg.Sessions > maxSessions {
		cfg.Sessions = maxSessions
	}
	if cfg.Net == nil {
		cfg.Net = &netx.Net{DNS: netx.DefaultDNS}
	}
	if cfg.DeviceID == "" {
		return nil, errors.New("device ID is required")
	}
	aead, err := wrap.NewAEAD(cfg.Link.Password)
	if err != nil {
		return nil, err
	}
	e := &Engine{cfg: cfg, aead: aead, b: newBind(), state: StateStopped, since: time.Now(), done: make(chan struct{})}
	e.target.Store(int32(cfg.Sessions))
	if cfg.Power == PowerBalanced || cfg.Power == PowerSaver {
		e.quiet = session.NewQuiet()
		e.b.quiet = e.quiet
	}
	e.gen = randomID()
	if _, err := rand.Read(e.keys.Private[:]); err != nil {
		return nil, err
	}
	e.keys.Private[0] &= 248
	e.keys.Private[31] = e.keys.Private[31]&127 | 64
	pub, err := curve25519.X25519(e.keys.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(e.keys.Public[:], pub)
	if len(cfg.Link.ServerKey) == 32 {
		e.mode.Store(modeDirect)
	}
	e.vk = &vkcreds.Client{
		HTTP:    &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: cfg.Net.Dialer().DialContext, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second}},
		Captcha: &captchaGate{e: e, next: cfg.Captcha},
		Cache:   &vkcreds.Cache{Path: cfg.VKCache},
		Logf:    e.logf,
	}
	// Groups start on guests 0..bases-1 of each call (startGuest).
	perHash := (cfg.Sessions + len(cfg.Link.Hashes) - 1) / max(1, len(cfg.Link.Hashes))
	bases := int32((perHash + perGuest - 1) / perGuest)
	for _, h := range cfg.Link.Hashes {
		e.hashes = append(e.hashes, &hashState{hash: h, cache: e.vk.Cache, start: time.Now(), bases: bases})
	}
	if len(e.hashes) == 0 {
		return nil, errors.New("no VK call in the link")
	}
	return e, nil
}

func (e *Engine) logf(format string, args ...any) {
	line, ok := e.logs.allow(fmt.Sprintf(format, args...), time.Now())
	if !ok {
		return
	}
	if e.cfg.Logf != nil {
		e.cfg.Logf("%s", line)
	}
	if !e.cfg.NoStats && statsLogLine(line) {
		noteEvent(line)
	}
}

// Start connects: it obtains the server's WireGuard config through the
// first session, creates the tunnel with mk and starts the remaining
// sessions in the background. It returns once traffic can flow.
func (e *Engine) Start(ctx context.Context, mk TunFactory) error {
	e.ctx, e.stop = context.WithCancel(context.Background())
	e.setState(StateConnecting, "")
	err := e.start(ctx, mk)
	if err != nil {
		e.fail(err)
		return err
	}
	return nil
}

func (e *Engine) start(ctx context.Context, mk TunFactory) error {
	var err error
	if e.peer, err = e.cfg.Net.ResolveUDP(ctx, e.cfg.Link.Peer()); err != nil {
		return fmt.Errorf("resolve server %s: %w", e.cfg.Link.Peer(), err)
	}
	// The first session: a few tries, across TURN servers. When VK asks
	// to slow down, wait as long as it says (up to firstWait in all)
	// instead of giving up.
	var first *session.Session
	waited := time.Duration(0)
	for attempt := 0; ; attempt++ {
		first, err = e.dial(ctx, 0, attempt)
		if err == nil {
			break
		}
		var we *waitError
		if errors.As(err, &we) && waited+we.Wait <= firstWait && ctx.Err() == nil && e.ctx.Err() == nil {
			e.logf("VK asks to wait %s before new credentials", we.Wait.Round(time.Second))
			if !sleep(ctx, we.Wait+500*time.Millisecond) {
				return ctx.Err()
			}
			waited += we.Wait
			attempt--
			continue
		}
		if fatal(err) || ctx.Err() != nil || e.ctx.Err() != nil || attempt >= 4 {
			return err
		}
		e.logf("first session failed (%v), retrying", err)
		if !sleep(ctx, time.Duration(1+attempt)*time.Second) {
			return ctx.Err()
		}
	}
	if first.Config == "" {
		first.Close()
		return errors.New("the server has no WireGuard config for this device (NOCONF)")
	}
	if e.wg, err = ParseWGConfig(first.Config); err != nil {
		first.Close()
		return err
	}
	td, err := mk(e.wg)
	if err != nil {
		first.Close()
		return fmt.Errorf("create tunnel: %w", err)
	}
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: func(f string, a ...any) { e.logf("wireguard: "+f, a...) }}
	// Attach the first session before WireGuard comes up, so that its first
	// handshake goes out at once instead of after the 5 s retry.
	e.b.add(first)
	e.dev = device.NewDevice(td, e.b, logger)
	uapi, err := e.wg.uapi()
	if err == nil {
		err = e.dev.IpcSet(uapi)
	}
	if err == nil {
		err = e.dev.Up()
	}
	if err != nil {
		e.b.remove(first)
		first.Close()
		e.dev.Close()
		return fmt.Errorf("WireGuard: %w", err)
	}
	e.logf("connected: address %s, MTU %d, %d VK call(s), %d sessions, %s protocol", e.wg.Address, e.wg.MTU, len(e.hashes), e.cfg.Sessions, e.protocol())

	e.workers.Add(e.cfg.Sessions)
	go e.worker(0, first)
	for i := 1; i < e.cfg.Sessions; i++ {
		go func(i int) {
			// Stagger the start so that TURN servers and VK see a ramp, not a burst.
			if !sleep(e.ctx, time.Duration(i)*250*time.Millisecond) {
				e.workers.Done()
				return
			}
			e.worker(i, nil)
		}(i)
	}
	go e.watchdog()
	go e.monitor()
	go e.statsLoop()
	return nil
}

// worker keeps session slot i alive.
func (e *Engine) worker(i int, s *session.Session) {
	defer e.workers.Done()
	backoff := time.Second
	// Only sessions that replace an earlier one count as reconnects.
	opened := s != nil
	fails := 0 // failed dials in a row: each tries the next TURN server
	for e.ctx.Err() == nil {
		if s == nil {
			// Fewer routes while VK refuses allocations, or while idle:
			// this slot rests.
			up := e.idleUp()
			if i > 0 && i >= e.limit() {
				if !e.rest(i, up) {
					return
				}
				continue
			}
			// No network: wait for one instead of failing route after route.
			if !e.offline.wait(e.ctx) {
				return
			}
			// The server answers no route: one route checks it.
			if !e.silent.wait(e.ctx) {
				return
			}
			var err error
			s, err = e.dial(e.ctx, i, fails)
			if err != nil {
				fails++
				if e.ctx.Err() != nil {
					return
				}
				if fatal(err) {
					e.fail(err)
					return
				}
				if unreachable(err) {
					if e.offline.down(time.Now(), offlineWait) {
						e.noteError("no network: new routes wait for it")
					}
					fails--
					continue
				}
				// VK allocated, but the WDTT server answers no route:
				// it is down (or its network is). One route checks it
				// now and then instead of every route, each costing a
				// VK allocation.
				if errors.Is(err, session.ErrNoWelcome) && e.mode.Load() == modeDirect && len(e.b.list()) == 0 {
					if d, news := e.silent.backoff(time.Now(), silentWait, silentWaitMax); news {
						e.noteError(fmt.Sprintf("the server does not answer: one route checks it every %s", d.Round(time.Second)))
					}
					fails--
					continue
				}
				// A wait for VK is logged once, where it starts (the
				// error that caused it), not by every session that waits.
				var we *waitError
				if !errors.As(err, &we) {
					e.noteError(fmt.Sprintf("session %d: %v", i, err))
					e.offline.up() // it failed, but not for lack of network
				}
				if !sleep(e.ctx, jitter(backoff)) {
					return
				}
				backoff = min(backoff*2, 30*time.Second)
				continue
			}
			fails = 0
			e.offline.up()
			e.silent.up()
			if i > 0 && i >= e.limit() {
				// Idle mode began while it opened.
				s.Close()
				s, opened = nil, false
				continue
			}
			if opened {
				e.reconnect.Add(1)
			}
			opened = true
		}
		n := len(e.b.list())
		if !e.b.has(s) {
			// Upload starts at the rate this TURN server allowed lately.
			s.Pace.Seed(e.learned.Start(s.Server))
			n = e.b.add(s)
			if n == 1 && e.hadSessions.Load() {
				// Every session had dropped: the server probably restarted
				// and lost the WireGuard session, so re-key now instead
				// of waiting for WireGuard's own timeout.
				e.rehandshake("the tunnel was down")
			}
		}
		e.hadSessions.Store(true)
		if n == 1 || e.State() != StateConnected {
			e.setState(StateConnected, "")
		} else {
			e.notify()
		}
		e.readLoop(s)
		e.learned.Note(s.Server, &s.Pace)
		e.b.remove(s)
		s.Close()
		e.rxClosed.Add(s.RxBytes.Load())
		e.txClosed.Add(s.TxBytes.Load())
		healthy := time.Since(s.Started) > time.Minute
		if healthy {
			backoff = time.Second
		}
		s = nil
		if e.ctx.Err() != nil {
			return
		}
		e.notify()
		if i > 0 && i >= e.limit() {
			// Closed for idle mode: it rests, and coming back is no
			// reconnect.
			opened = false
			continue
		}
		// A route that served for a while is replaced at once, unless many
		// went down together (a network switch, a server restart): then
		// the new allocations are spread out.
		wait := jitter(backoff)
		if t := e.limit(); healthy && t-len(e.b.list()) <= max(1, t/4) {
			wait = 0
		}
		if wait > 0 && !sleep(e.ctx, wait) {
			return
		}
	}
}

func (e *Engine) readLoop(s *session.Session) {
	for {
		buf := getBuf()
		n, err := s.Read(buf)
		if err != nil {
			putBuf(buf)
			if d := s.Denied(); d != nil && e.ctx.Err() == nil {
				e.fail(d)
			}
			return
		}
		if s.Direct() {
			e.b.deliverOrdered(buf[:n])
		} else {
			e.b.deliver(buf[:n])
		}
	}
}

// dial opens session slot i: its VK call is i mod len(hashes), its TURN
// server rotates through the servers VK returned; shift moves it on, so
// that a slot whose TURN server stopped answering tries the next one.
func (e *Engine) dial(ctx context.Context, i, shift int) (*session.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	hs, g, creds, err := e.creds(ctx, i)
	if err != nil {
		return nil, err
	}
	e.probeRelays(creds.Servers)
	server := e.cfg.TURNServer
	if server == "" {
		server = creds.Servers[(i/len(e.hashes)+shift)%len(creds.Servers)]
		if !e.cfg.NoRelayScoring && shift == 0 {
			server = e.relays.pick(creds.Servers, server, e.b.list())
		}
	}
	mode := e.mode.Load()
	p := session.Params{
		Peer: e.peer, TURNServer: server, Username: creds.Username, Password: creds.Password,
		AEAD: e.aead, Mode: e.cfg.Mode, Net: e.cfg.Net,
		ConnPassword: e.cfg.Link.Password, DeviceID: e.cfg.DeviceID, Generation: e.gen, Worker: i,
		OnReset: e.serverReset, Logf: e.logf, OnUnfreed: e.noteUnfreed, RTTs: &e.rtts, Quiet: e.quiet,
		NetDown: func() bool { return e.netDown(time.Now()) },
		Direct:  mode != modeDTLS, Keys: &e.keys, ServerKey: e.cfg.Link.ServerKey,
	}
	if mode == modeUnknown {
		p.DirectTimeout = 4 * time.Second
	}
	s, err := session.Dial(ctx, p)
	defer func() {
		if s != nil {
			s.StatsAck = e.statsAck
		}
	}()
	if mode == modeUnknown {
		switch {
		case err == nil:
			e.mode.CompareAndSwap(modeUnknown, modeDirect)
		case errors.Is(err, session.ErrNoWelcome):
			// Not a TurnVK server (or a wrong password): the standard
			// protocol, on a fresh allocation.
			e.logf("the server does not speak the direct protocol, using DTLS")
			e.mode.CompareAndSwap(modeUnknown, modeDTLS)
			p.Direct = false
			s, err = session.Dial(ctx, p)
		}
	}
	var te *session.TURNError
	switch {
	case errors.As(err, &te) && te.QuotaReached():
		now := time.Now()
		e.quotaAt.Store(now.UnixNano())
		if n, moved := hs.nextGuest(g, creds, now); moved {
			e.logf("VK call %s…: the guest has no allocations left, group %d moves to guest %d", short(hs.hash), g+1, n+1)
		} else if wait, first := hs.quotaBackoff(g, now); first {
			// Every guest is at VK's limit (allocations of closed routes
			// still count until VK frees them): new credentials would not
			// help, waiting and fewer routes do.
			e.logf("VK call %s…: no allocations left for group %d, it waits %s", short(hs.hash), g+1, wait.Round(time.Second))
			e.lowerTarget(now)
		}
	case errors.As(err, &te) && te.CredentialsRejected():
		hs.invalidate(g, creds)
	case err == nil:
		cs := hs.slot(g)
		cs.quotaFails.Store(0)
		hs.cache.Hold(hs.guestKey(cs.guest.Load()), time.Now())
	case errors.As(err, &te), err != nil && ctx.Err() != nil && e.ctx.Err() == nil && !unreachable(err):
		// The TURN server did not allocate, or the route never came up.
		if e.cfg.TURNServer == "" {
			e.relays.failed(server, time.Now())
		}
	}
	return s, err
}

// creds returns the TURN credentials for slot i, skipping dead calls.
func (e *Engine) creds(ctx context.Context, i int) (*hashState, int, *vkcreds.Creds, error) {
	var last error
	n := len(e.hashes)
	g := (i / n) / perCreds
	for k := 0; k < n; k++ {
		hs := e.hashes[(i+k)%n]
		c, err := hs.get(ctx, e, g)
		if err == nil {
			return hs, g, c, nil
		}
		last = err
		var ce *vkcreds.CallError
		if !errors.As(err, &ce) {
			return nil, 0, nil, err
		}
	}
	return nil, 0, nil, fmt.Errorf("no usable VK call: %w", last)
}

func (hs *hashState) slot(g int) *credSlot {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.groups == nil {
		hs.groups = map[int]*credSlot{}
	}
	cs := hs.groups[g]
	if cs == nil {
		cs = &credSlot{}
		cs.guest.Store(hs.startGuest(int32(g*perCreds/perGuest), time.Now()))
		// Credentials saved by an earlier run: no VK request at all.
		if c := hs.cache.Creds(hs.credsKey(g, cs)); c != nil {
			cs.cur.Store(c)
		}
		hs.groups[g] = cs
	}
	return cs
}

// busy tells whether an earlier run left guest x's allocations unfreed
// lately (the app was killed, or stopped without network): VK may still
// count them. hs.mu is held.
func (hs *hashState) busy(x int32, now time.Time) bool {
	t := hs.cache.Held(hs.guestKey(x))
	return t.Before(hs.start.Truncate(time.Second)) && now.Sub(t) < allocLife // saved in seconds
}

// startGuest picks the guest a group starts with: its own (base), unless
// an earlier run left it busy; then a guest no group starts with, the
// same for both groups of the guest, so the first routes do not all meet
// error 486. hs.mu is held.
func (hs *hashState) startGuest(base int32, now time.Time) int32 {
	if to, ok := hs.moved[base]; ok {
		return to
	}
	if !hs.busy(base, now) {
		return base
	}
	taken := map[int32]bool{}
	for _, to := range hs.moved {
		taken[to] = true
	}
	for x := hs.bases; x < maxGuests; x++ {
		if !taken[x] && !hs.busy(x, now) {
			if hs.moved == nil {
				hs.moved = map[int32]int32{}
			}
			hs.moved[base] = x
			return x
		}
	}
	return base
}

// guestKey names guest x of the call in the cache's holds.
func (hs *hashState) guestKey(x int32) string {
	return fmt.Sprintf("%s#%d", hs.hash, x)
}

// holdGuests notes the guests whose routes hold allocations now (saved
// at most once a minute), so that a run killed later knows which are busy.
func (hs *hashState) holdGuests(now time.Time) {
	hs.mu.Lock()
	var gs []int32
	for _, cs := range hs.groups {
		if cs.cur.Load() != nil {
			gs = append(gs, cs.guest.Load())
		}
	}
	hs.mu.Unlock()
	for _, x := range gs {
		hs.cache.Hold(hs.guestKey(x), now)
	}
}

// freeGuests forgets the holds this run made: its allocations were freed.
func (hs *hashState) freeGuests() {
	var keys []string
	for x := int32(0); x < maxGuests; x++ {
		if k := hs.guestKey(x); !hs.cache.Held(k).Before(hs.start.Truncate(time.Second)) {
			keys = append(keys, k)
		}
	}
	hs.cache.Free(keys...)
}

// noteUnfreed: a route's allocation could not be freed.
func (e *Engine) noteUnfreed() { e.unfreedAt.Store(time.Now().UnixNano()) }

func (hs *hashState) blocked() error {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.dead != nil {
		return hs.dead
	}
	if wait := time.Until(hs.waitUntil); wait > 0 {
		return &waitError{wait}
	}
	return nil
}

// waitError: VK asked to slow down (or a captcha was passed over); new
// credentials can be asked for after Wait.
type waitError struct{ Wait time.Duration }

func (e *waitError) Error() string {
	return fmt.Sprintf("VK credentials: retrying in %s", e.Wait.Round(time.Second))
}

// get returns credentials for group g. Credentials past their refresh
// time but not yet expired are returned at once while fresh ones are
// fetched in the background: a captcha nobody has solved yet, or a rate
// limit, never holds up a new session.
func (hs *hashState) get(ctx context.Context, e *Engine, g int) (*vkcreds.Creds, error) {
	cs := hs.slot(g)
	if wait := time.Duration(cs.quotaUntil.Load() - time.Now().UnixNano()); wait > 0 {
		return nil, &waitError{wait}
	}
	if c := cs.cur.Load(); c != nil {
		if c.Fresh() {
			return c, nil
		}
		if c.Usable(10 * time.Minute) {
			if cs.bg.CompareAndSwap(false, true) {
				go func() {
					defer cs.bg.Store(false)
					_, _ = hs.fetch(e.ctx, e, g, cs)
				}()
			}
			return c, nil
		}
	}
	return hs.fetch(ctx, e, g, cs)
}

func (hs *hashState) fetch(ctx context.Context, e *Engine, g int, cs *credSlot) (*vkcreds.Creds, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if c := cs.cur.Load(); c != nil && c.Fresh() {
		return c, nil
	}
	if err := hs.blocked(); err != nil {
		return nil, err
	}
	c, err := e.vk.FetchAs(ctx, hs.hash, int(cs.guest.Load()))
	if err != nil {
		var ce *vkcreds.CallError
		var ae *vkcreds.APIError
		hs.mu.Lock()
		switch {
		case errors.As(err, &ce):
			hs.dead = err
			e.logf("VK call %s… is unusable: %v", short(hs.hash), err)
		case errors.Is(err, vkcreds.ErrCaptchaRequired):
			// While the previous credentials still work, a captcha the
			// user passed over is not asked again for a while.
			wait := 60 * time.Second
			if c := cs.cur.Load(); c != nil && c.Usable(10*time.Minute) {
				wait = 15 * time.Minute
			}
			hs.waitUntil = time.Now().Add(wait)
		case errors.As(err, &ae) && ae.RateLimited():
			hs.waitUntil = time.Now().Add(30 * time.Second)
		default:
			hs.waitUntil = time.Now().Add(5 * time.Second)
		}
		hs.mu.Unlock()
		return nil, err
	}
	e.logf("VK call %s… group %d: TURN credentials, %d server(s)", short(hs.hash), g+1, len(c.Servers))
	cs.cur.Store(c)
	hs.cache.PutCreds(hs.credsKey(g, cs), c)
	return c, nil
}

// guestRest: a guest that hit VK's allocation limit is not moved to
// again for this long (its allocations expire meanwhile).
const guestRest = 5 * time.Minute

// nextGuest moves group g to a guest no other group uses and that has
// not hit VK's limit lately, after VK refused its guest more allocations.
// c are the refused credentials: a group already moved is left alone.
// With no such guest the group keeps its guest and credentials.
func (hs *hashState) nextGuest(g int, c *vkcreds.Creds, now time.Time) (int, bool) {
	cs := hs.slot(g)
	if cs.cur.Load() != c {
		return 0, false
	}
	hs.mu.Lock()
	if hs.full == nil {
		hs.full = map[int32]time.Time{}
	}
	old := cs.guest.Load()
	hs.full[old] = now
	used := map[int32]bool{}
	for _, o := range hs.groups {
		used[o.guest.Load()] = true
	}
	n := int32(-1)
	for k := int32(1); k < maxGuests; k++ {
		x := (old + k) % maxGuests
		if !used[x] && now.Sub(hs.full[x]) > guestRest && !hs.busy(x, now) {
			n = x
			break
		}
	}
	hs.mu.Unlock()
	if n < 0 || !cs.cur.CompareAndSwap(c, nil) {
		return 0, false
	}
	hs.cache.PutCreds(hs.credsKey(g, cs), nil)
	cs.guest.Store(n)
	return int(n), true
}

// quotaBackoff holds group g's new routes back after error 486 with no
// guest to move to; first is true when the wait starts (not when a route
// already on its way hits the limit too).
func (hs *hashState) quotaBackoff(g int, now time.Time) (time.Duration, bool) {
	cs := hs.slot(g)
	if cs.quotaUntil.Load() > now.UnixNano() {
		return 0, false
	}
	n := cs.quotaFails.Add(1)
	wait := min(quotaWait<<min(n-1, 3), quotaWaitMax)
	cs.quotaUntil.Store(now.Add(wait).UnixNano())
	return wait, true
}

// lowerTarget uses targetStep fewer routes (down to half the set number)
// after error 486, at most once per quotaWait.
func (e *Engine) lowerTarget(now time.Time) {
	// Right after more routes were tried: that number does not fit, and
	// the next try waits longer. Later: it did fit.
	afterRaise := false
	if r := e.raisedAt.Swap(0); r > 0 {
		if now.UnixNano()-r < int64(raiseProbe) {
			afterRaise = true
			e.raiseFails.Store(min(e.raiseFails.Load()+1, 2))
		} else {
			e.raiseFails.Store(0)
		}
	}
	t := e.target.Load()
	floor := int32(max(1, e.cfg.Sessions/2))
	last := e.targetAt.Load()
	if t <= floor || (!afterRaise && now.UnixNano()-last < int64(quotaWait)) || !e.targetAt.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	n := max(floor, t-targetStep)
	e.target.Store(n)
	e.logf("VK refuses more TURN allocations: using %d routes instead of %d for a while", n, e.cfg.Sessions)
	e.notify()
}

// raiseTarget tries targetStep more routes after targetRestore without
// error 486 (twice or four times as long when the last tries met 486 at
// once).
func (e *Engine) raiseTarget(now time.Time) {
	t := e.target.Load()
	if int(t) >= e.cfg.Sessions {
		return
	}
	ns := now.UnixNano()
	last := e.targetAt.Load()
	restore := int64(targetRestore) << e.raiseFails.Load()
	if ns-e.quotaAt.Load() < restore || ns-last < restore || !e.targetAt.CompareAndSwap(last, ns) {
		return
	}
	n := min(int32(e.cfg.Sessions), t+targetStep)
	e.target.Store(n)
	e.raisedAt.Store(ns)
	e.logf("trying %d routes again", n)
	e.notify()
}

func (hs *hashState) invalidate(g int, c *vkcreds.Creds) {
	if time.Since(c.Fetched) > 15*time.Second {
		cs := hs.slot(g)
		if cs.cur.CompareAndSwap(c, nil) {
			hs.cache.PutCreds(hs.credsKey(g, cs), nil)
		}
	}
}

// credsKey names group g's saved credentials: the call, its guest, the group.
func (hs *hashState) credsKey(g int, cs *credSlot) string {
	return fmt.Sprintf("%s#%d/%d", hs.hash, cs.guest.Load(), g)
}

// watchdog recycles the sessions when the server has gone silent:
//   - the tunnel is in use (packets go out) but nothing has come back for
//     silentActive: a server that lost our sessions without telling us;
//   - nothing at all has come back for staleRx: with WireGuard re-keying
//     every two minutes a healthy tunnel always receives within that.
func (e *Engine) watchdog() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	lastRx, rxAt := e.b.rx.Load(), time.Now()
	txAtRx := e.b.tx.Load()
	lastTick := time.Now().UnixNano() // wall clock: it runs on while the device sleeps
	e.idleStart(time.Now())
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-t.C:
		}
		list := e.b.list()
		// After sleep the routes renew their TURN allocations and
		// permissions: pion's timers stood still meanwhile, VK's did not
		// (session/renew.go).
		at := time.Now()
		for _, s := range list {
			s.RenewTURN(at)
		}
		if wall := time.Now().UnixNano(); wall-lastTick > int64(sleepGap) {
			// The device slept (Android in the background): timers stopped
			// and every route missed its pings. Give them time before
			// judging any; after a long sleep ask each route now.
			e.wokeAt.Store(wall)
			e.wakes.Add(1)
			if gap := time.Duration(wall - lastTick); gap >= sleepCheck {
				e.logf("the device was asleep for %s, checking the routes", gap.Round(time.Second))
				for _, s := range list {
					go s.Probe()
				}
			}
			lastTick = wall
			lastRx, rxAt, txAtRx = e.b.rx.Load(), time.Now(), e.b.tx.Load()
			e.idle.prevPk = e.b.rx.Load() + e.b.tx.Load()
			e.idle.busyRun = 0 // seconds apart are no run
			continue
		} else {
			lastTick = wall
		}
		e.replaceSilentPaths(list)
		now := time.Now()
		e.idleTick(now, list)
		e.raiseTarget(now)
		if len(list) > 0 {
			for _, hs := range e.hashes {
				hs.holdGuests(now)
			}
		}
		if !e.cfg.NoRelayScoring && e.relays.tick(list, now) && e.mayMove(now) {
			if s := e.relays.moveOne(list); s != nil {
				e.movedAt.Store(now.UnixNano())
				e.logf("route %d: TURN server %s %s, moving the route to a better one", s.ID, s.Server, e.relays.why(s.Server))
				s.Close()
			}
		}
		if rx := e.b.rx.Load(); rx != lastRx || len(list) == 0 {
			lastRx, rxAt, txAtRx = rx, time.Now(), e.b.tx.Load()
			continue
		}
		silent := time.Since(rxAt)
		reason := ""
		direct := e.mode.Load() == modeDirect
		switch {
		case direct && silent > silentProbe && e.b.tx.Load()-txAtRx >= 5:
			// Direct paths are probed, not dropped, so look early.
			reason = fmt.Sprintf("no answer from the server for %s while sending", silent.Round(time.Second))
		case silent > silentActive && e.b.tx.Load()-txAtRx >= 10:
			reason = fmt.Sprintf("no answer from the server for %s while sending", silent.Round(time.Second))
		case silent > staleRx:
			reason = "no data from the server for 3 minutes"
		}
		if reason == "" {
			continue
		}
		if e.mode.Load() == modeDirect {
			// Each path answers pings: find the dead ones and replace
			// only those; the others keep the tunnel up.
			if e.probing.CompareAndSwap(false, true) {
				go e.replaceDeadPaths(reason, silent, list)
			}
			lastRx, rxAt, txAtRx = e.b.rx.Load(), time.Now(), e.b.tx.Load()
			continue
		}
		if e.netDown(now) {
			e.holdRoutes(now)
			lastRx, rxAt, txAtRx = e.b.rx.Load(), time.Now(), e.b.tx.Load()
			continue
		}
		e.noteError(reason + ", reconnecting all sessions")
		for _, s := range list {
			s.Close()
		}
		lastRx, rxAt, txAtRx = e.b.rx.Load(), time.Now(), e.b.tx.Load()
	}
}

// mayMove tells whether a route may move to a better relay now: one move
// per relayMoveEvery, none while VK refuses allocations (a move frees one
// and asks for another) or while the device dozes.
func (e *Engine) mayMove(now time.Time) bool {
	ns := now.UnixNano()
	return ns-e.movedAt.Load() >= int64(relayMoveEvery) &&
		ns-e.quotaAt.Load() >= int64(quotaCalm) &&
		ns-e.wokeAt.Load() >= int64(dozeWindow) &&
		!e.quiet.Relaxed(now)
}

// replaceSilentPaths closes direct paths that have not heard from the
// server for pathReplace while others have (their workers open new ones
// at once). A path that is merely slow keeps answering pings; one that VK
// stopped relaying would otherwise linger until pathDead. When no path
// answers, the server is the likely problem: the watchdog handles that.
func (e *Engine) replaceSilentPaths(list []*session.Session) {
	if e.mode.Load() != modeDirect || len(list) < 2 {
		return
	}
	now := time.Now()
	// Just after the device slept (the phone in the background), every
	// route looks silent until its next ping comes back: wait for them.
	// While idle the routes ping only at each burst: pathDead judges them.
	if now.UnixNano()-e.wokeAt.Load() < int64(wakeGrace) || e.quiet.Relaxed(now) || e.netDown(now) {
		return
	}
	fresh := 0
	for _, s := range list {
		if s.Fresh(now) {
			fresh++
		}
	}
	if fresh == 0 {
		return
	}
	// A dozing phone pauses the pings too: give paths longer.
	replaceAfter := pathReplace
	if now.UnixNano()-e.wokeAt.Load() < int64(dozeWindow) {
		replaceAfter = dozeReplace
	}
	total, heard := map[string]int{}, map[string]int64{}
	var cands []*session.Session
	for _, s := range list {
		total[s.Server]++
		heard[s.Server] = max(heard[s.Server], s.LastRx.Load())
		if s.Direct() && s.Silent(now) > replaceAfter && time.Since(s.Started) > pathReplace {
			cands = append(cands, s)
		}
	}
	if len(cands) == 0 {
		return
	}
	silent := map[string]int{}
	for _, s := range cands {
		silent[s.Server]++
	}
	// Every route through a TURN server fell silent while routes through
	// another kept answering after it: that server stopped relaying. New
	// routes go elsewhere for a while instead of waiting out its
	// allocation timeout. When the WDTT server restarts or the device
	// loses the network, every route stops at about the same moment and
	// none answers later: no relay is to blame.
	down := map[string]bool{}
	for sv, n := range silent {
		if n == total[sv] && n >= 2 && answeredAfter(list, sv, heard[sv]) >= 2 && e.cfg.TURNServer == "" {
			down[sv] = true
			e.logf("TURN server %s stopped relaying, new routes avoid it for %s", sv, relayDownFor)
			e.relays.failed(sv, now)
		}
	}
	// Many routes silent at once (not on one dead TURN server) is the
	// network or the device pausing, not the routes: new allocations would
	// not help and every one costs VK's limits. Probe them; a route that
	// stays silent is closed by its own pathDead.
	limit := max(2, len(list)/4)
	if len(cands) > limit {
		n := 0
		for _, s := range cands {
			if down[s.Server] {
				s.Close()
				n++
			} else {
				s.Probe()
			}
		}
		if last := e.massSilentLog.Load(); n < len(cands) && now.UnixNano()-last > int64(time.Minute) && e.massSilentLog.CompareAndSwap(last, now.UnixNano()) {
			e.logf("%d of %d routes silent at once: checking them instead of replacing", len(cands)-n, len(list))
		}
		return
	}
	for _, s := range cands {
		e.logf("route %d (%s) silent for %s, replacing it", s.ID, s.Server, s.Silent(now).Round(time.Second))
		s.Close()
	}
}

// answeredAfter counts routes through other TURN servers that heard from
// the WDTT server well after the last route through sv did (a ping round
// later): proof that the server and the network were still there.
func answeredAfter(list []*session.Session, sv string, last int64) int {
	n := 0
	for _, s := range list {
		if s.Server != sv && s.LastRx.Load() > last+int64(relayDownProof) {
			n++
		}
	}
	return n
}

// replaceDeadPaths probes every path and closes those that do not answer
// (their workers open new ones). If none answers, the server is likely
// gone or restarted: WireGuard re-keys once paths are back.
func (e *Engine) replaceDeadPaths(reason string, silent time.Duration, list []*session.Session) {
	defer e.probing.Store(false)
	// No network: nothing would answer, and nothing new could open.
	if now := time.Now(); e.netDown(now) {
		e.holdRoutes(now)
		return
	}
	for _, s := range list {
		s.Probe()
	}
	if !sleep(e.ctx, 2500*time.Millisecond) {
		return
	}
	now := time.Now()
	dead := 0
	for _, s := range list {
		if !s.Fresh(now) {
			s.Close()
			dead++
		}
	}
	switch {
	case dead == 0:
		// Every path answers: the traffic itself may simply get no
		// reply. Only a long silence suggests lost WireGuard keys.
		if silent >= silentActive {
			e.logf("%s; every path answers, re-keying", reason)
			e.rehandshake("silent tunnel")
		}
	case dead == len(list):
		e.noteError(fmt.Sprintf("%s; no path answers, reconnecting", reason))
	default:
		e.logf("%s; replacing %d of %d paths that stopped answering", reason, dead, len(list))
	}
}

// Stop disconnects and releases the tunnel.
func (e *Engine) Stop() {
	if e.stop != nil {
		e.stop()
	}
	for _, s := range e.b.list() {
		s.Close()
	}
	if e.dev != nil {
		e.dev.Close()
	}
	waitTimeout(&e.workers, 5*time.Second)
	// Free the TURN allocations before the app exits, or VK keeps counting
	// them against the next start (error 486).
	// All freed (none left unfreed lately): the next start may use the
	// same guests at once.
	if session.WaitReleased(3*time.Second) && time.Since(time.Unix(0, e.unfreedAt.Load())) > allocLife {
		for _, hs := range e.hashes {
			hs.freeGuests()
		}
	}
	e.mu.Lock()
	failed := e.state == StateFailed
	if !failed {
		e.state = StateStopped
	}
	e.mu.Unlock()
	if !failed && !e.cfg.NoStats {
		if e.diag.connectedUnix() == 0 {
			noteDown("connecting was stopped", time.Now())
		} else {
			noteDown("stopped by the app", time.Now())
		}
	}
	e.finish()
	e.notify()
}

// Done is closed when the engine stops or fails.
func (e *Engine) Done() <-chan struct{} { return e.done }

// Err is the fatal error that stopped the engine, if any.
func (e *Engine) Err() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.fatal
}

// WG returns the server's WireGuard config (nil before Start succeeds).
func (e *Engine) WG() *WGConfig { return e.wg }

func (e *Engine) finish() { e.doneOnce.Do(func() { close(e.done) }) }

func (e *Engine) fail(err error) {
	e.mu.Lock()
	if e.fatal == nil {
		e.fatal = err
	}
	e.state = StateFailed
	e.lastErr = err.Error()
	e.since = time.Now()
	e.mu.Unlock()
	e.logf("stopped: %v", err)
	if !e.cfg.NoStats {
		noteDown("failed: "+err.Error(), time.Now())
	}
	if e.stop != nil {
		e.stop()
	}
	for _, s := range e.b.list() {
		s.Close()
	}
	if e.dev != nil {
		go e.dev.Close()
	}
	e.finish()
	e.notify()
}

// State returns the current state.
func (e *Engine) State() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state
}

func (e *Engine) setState(state, errText string) {
	e.mu.Lock()
	if e.state == StateFailed {
		e.mu.Unlock()
		return
	}
	if e.state != state {
		e.since = time.Now()
	}
	e.state = state
	if errText != "" {
		e.lastErr = errText
	}
	e.mu.Unlock()
	e.notify()
}

func (e *Engine) noteError(msg string) {
	e.logf("%s", msg)
	e.mu.Lock()
	e.lastErr = msg
	e.mu.Unlock()
	if len(e.b.list()) == 0 && e.State() == StateConnected {
		e.setState(StateConnecting, "")
	}
}

// Status returns a snapshot.
func (e *Engine) Status() Status {
	list := e.b.list()
	// Routes opened before VK refused more keep running: the target
	// limits new ones, so it is never shown below the routes there are.
	st := Status{Sessions: len(list), Target: max(int(e.target.Load()), len(list)), RxBytes: e.rxClosed.Load(), TxBytes: e.txClosed.Load(), Reconnects: e.reconnect.Load()}
	for _, s := range list {
		st.RxBytes += s.RxBytes.Load()
		st.TxBytes += s.TxBytes.Load()
	}
	now := time.Now()
	for _, s := range list {
		ps := PathStatus{ID: s.ID, Server: s.Server, RTT: int(s.RTT.Load() / int64(time.Millisecond)), Fresh: s.Fresh(now), Rx: s.RxBytes.Load(), Tx: s.TxBytes.Load(), RxPackets: s.RxPackets.Load(), Lost: s.RxLost.Load()}
		if s.Pace.HasFeedback() {
			rate, loss, q := s.Pace.State()
			ps.UpRate, ps.UpLoss, ps.UpQueue = int(rate), loss, int(q/time.Millisecond)
		}
		st.Paths = append(st.Paths, ps)
	}
	sum, n := int64(0), int64(0)
	for _, s := range list {
		if r := s.RTT.Load(); r > 0 {
			sum += r
			n++
		}
	}
	if n > 0 {
		st.RTT = int(sum / n / int64(time.Millisecond))
	}
	st.Protocol = e.protocol()
	st.Quiet = e.quiet.On()
	e.mu.Lock()
	st.State, st.LastError, st.Since = e.state, e.lastErr, e.since.Unix()
	e.mu.Unlock()
	if e.captchas.Load() > 0 && st.State != StateFailed && st.State != StateStopped {
		st.Captcha = true
		if st.State != StateConnected || st.Sessions == 0 {
			st.State = StateCaptcha
		}
	}
	if e.wg != nil {
		st.Address = e.wg.Address.String()
	}
	return st
}

func (e *Engine) protocol() string {
	switch e.mode.Load() {
	case modeDirect:
		return "direct"
	case modeDTLS:
		return "dtls"
	}
	return ""
}

func (e *Engine) notify() {
	if e.cfg.OnStatus != nil {
		e.cfg.OnStatus(e.Status())
	}
}

// captchaGate reports the captcha state while the user solves one.
type captchaGate struct {
	e    *Engine
	next vkcreds.CaptchaSolver
}

func (g *captchaGate) SolveCaptcha(ctx context.Context, uri string) (string, error) {
	if g.next == nil {
		return "", vkcreds.ErrCaptchaRequired
	}
	g.e.captchas.Add(1)
	g.e.notify()
	defer func() { g.e.captchas.Add(-1); g.e.notify() }()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	return g.next.SolveCaptcha(ctx, uri)
}

func fatal(err error) bool {
	var d *session.DeniedError
	return errors.As(err, &d)
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(mrand.Int64N(int64(d)))
}

func waitTimeout(wg *sync.WaitGroup, d time.Duration) {
	c := make(chan struct{})
	go func() { wg.Wait(); close(c) }()
	select {
	case <-c:
	case <-time.After(d):
	}
}

func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// Reconnect drops every session; the platform calls it when the device
// switches networks (Wi-Fi <-> mobile), where old sockets die silently.
// Workers reconnect at once and WireGuard re-keys when the first is back.
func (e *Engine) Reconnect(why string) {
	if e.ctx == nil || e.ctx.Err() != nil {
		return
	}
	e.logf("reconnecting: %s", why)
	e.netChg.Add(1)
	e.offline.up()
	e.silent.up()
	for _, s := range e.b.list() {
		s.Close()
	}
}

// serverReset handles a session the server no longer knew: the server has
// most likely restarted and lost every session and its WireGuard state.
// Each other session is probed (a stale one gets its own reset and closes)
// and WireGuard re-keys at once.
func (e *Engine) serverReset() {
	now := time.Now().UnixNano()
	if last := e.lastReset.Load(); now-last < int64(2*time.Second) || !e.lastReset.CompareAndSwap(last, now) {
		return
	}
	e.logf("the server reset a session (restarted?), checking the others")
	for _, s := range e.b.list() {
		go s.Probe()
	}
	e.rehandshake("the server reset a session")
}

// Context ends when the engine stops (Background before Start; set
// there, before the engine is handed to anyone).
func (e *Engine) Context() context.Context {
	if e.ctx == nil {
		return context.Background()
	}
	return e.ctx
}
