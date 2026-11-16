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
	// OnStatus is called (from any goroutine) when the status changes.
	OnStatus func(Status)
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
	RTT      int    `json:"rtt_ms,omitempty"` // average over the paths
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
	captchas  atomic.Int32

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
}

type credSlot struct {
	mu    sync.Mutex // held while fetching
	cur   atomic.Pointer[vkcreds.Creds]
	bg    atomic.Bool  // a background refresh is running
	guest atomic.Int32 // which guest of the call fetches for this group
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
	for _, h := range cfg.Link.Hashes {
		e.hashes = append(e.hashes, &hashState{hash: h, cache: e.vk.Cache})
	}
	if len(e.hashes) == 0 {
		return nil, errors.New("no VK call in the link")
	}
	return e, nil
}

func (e *Engine) logf(format string, args ...any) {
	if e.cfg.Logf != nil {
		e.cfg.Logf(format, args...)
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
				// A wait for VK is logged once, where it starts (the
				// error that caused it), not by every session that waits.
				var we *waitError
				if !errors.As(err, &we) {
					e.noteError(fmt.Sprintf("session %d: %v", i, err))
				}
				if !sleep(e.ctx, jitter(backoff)) {
					return
				}
				backoff = min(backoff*2, 30*time.Second)
				continue
			}
			fails = 0
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
		// A route that served for a while is replaced at once, unless many
		// went down together (a network switch, a server restart): then
		// the new allocations are spread out.
		wait := jitter(backoff)
		if healthy && e.cfg.Sessions-len(e.b.list()) <= max(1, e.cfg.Sessions/4) {
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
		OnReset: e.serverReset, Logf: e.logf,
		Direct: mode != modeDTLS, Keys: &e.keys, ServerKey: e.cfg.Link.ServerKey,
	}
	if mode == modeUnknown {
		p.DirectTimeout = 4 * time.Second
	}
	s, err := session.Dial(ctx, p)
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
		if n, moved := hs.nextGuest(g, creds); moved {
			e.logf("VK call %s…: the guest has no allocations left, group %d moves to guest %d", short(hs.hash), g+1, n+1)
		}
	case errors.As(err, &te) && te.CredentialsRejected():
		hs.invalidate(g, creds)
	case errors.As(err, &te), err != nil && ctx.Err() != nil && e.ctx.Err() == nil:
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
		cs.guest.Store(int32(g * perCreds / perGuest))
		// Credentials saved by an earlier run: no VK request at all.
		if c := hs.cache.Creds(hs.credsKey(g, cs)); c != nil {
			cs.cur.Store(c)
		}
		hs.groups[g] = cs
	}
	return cs
}

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

// nextGuest moves group g to a guest no other group uses, after VK
// refused its guest more allocations. c are the refused credentials: a
// group already moved is left alone.
func (hs *hashState) nextGuest(g int, c *vkcreds.Creds) (int, bool) {
	cs := hs.slot(g)
	if !cs.cur.CompareAndSwap(c, nil) {
		return 0, false
	}
	hs.cache.PutCreds(hs.credsKey(g, cs), nil)
	hs.mu.Lock()
	n := int32(0)
	for _, o := range hs.groups {
		n = max(n, o.guest.Load())
	}
	hs.mu.Unlock()
	if n+1 >= maxGuests {
		return 0, false
	}
	cs.guest.Store(n + 1)
	return int(n + 1), true
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
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-t.C:
		}
		list := e.b.list()
		e.replaceSilentPaths(list)
		if !e.cfg.NoRelayScoring && e.relays.tick(list, time.Now()) {
			if s := e.relays.moveOne(list); s != nil {
				e.logf("route %d: TURN server %s loses %.1f%% of the packets, moving the route to a better one", s.ID, s.Server, 100*e.relays.lossOf(s.Server))
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
		e.noteError(reason + ", reconnecting all sessions")
		for _, s := range list {
			s.Close()
		}
		lastRx, rxAt, txAtRx = e.b.rx.Load(), time.Now(), e.b.tx.Load()
	}
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
	fresh := 0
	for _, s := range list {
		if s.Fresh(now) {
			fresh++
		}
	}
	if fresh == 0 {
		return
	}
	total, silent := map[string]int{}, map[string]int{}
	for _, s := range list {
		total[s.Server]++
		if s.Direct() && s.Silent(now) > pathReplace && time.Since(s.Started) > pathReplace {
			silent[s.Server]++
			e.logf("route %d (%s) silent for %s, replacing it", s.ID, s.Server, s.Silent(now).Round(time.Second))
			s.Close()
		}
	}
	// Every route through a TURN server fell silent at once: the server
	// itself stopped relaying. New routes go elsewhere for a while instead
	// of waiting out its allocation timeout one by one.
	for sv, n := range silent {
		if n == total[sv] && n >= 2 && e.cfg.TURNServer == "" {
			e.logf("TURN server %s stopped relaying, new routes avoid it for %s", sv, relayDownFor)
			e.relays.failed(sv, now)
		}
	}
}

// replaceDeadPaths probes every path and closes those that do not answer
// (their workers open new ones). If none answers, the server is likely
// gone or restarted: WireGuard re-keys once paths are back.
func (e *Engine) replaceDeadPaths(reason string, silent time.Duration, list []*session.Session) {
	defer e.probing.Store(false)
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
	session.WaitReleased(3 * time.Second)
	e.mu.Lock()
	if e.state != StateFailed {
		e.state = StateStopped
	}
	e.mu.Unlock()
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
	st := Status{Sessions: len(list), Target: e.cfg.Sessions, RxBytes: e.rxClosed.Load(), TxBytes: e.txClosed.Load(), Reconnects: e.reconnect.Load()}
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
