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
	Logf       func(format string, args ...any)
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
}

const (
	defaultSessions = 16
	maxSessions     = 64
	setupTimeout    = 45 * time.Second
	staleRx         = 180 * time.Second
	silentActive    = 8 * time.Second
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
	rekeying    atomic.Bool
	lastReset   atomic.Int64
}

// rehandshake drops WireGuard's current keys and starts a new handshake.
func (e *Engine) rehandshake(why string) {
	if e.dev == nil || !e.rekeying.CompareAndSwap(false, true) {
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
	hash string

	mu        sync.Mutex
	dead      error
	waitUntil time.Time
	groups    map[int]*credSlot
}

type credSlot struct {
	mu    sync.Mutex
	creds *vkcreds.Creds
}

const perCreds = 8

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
	e.vk = &vkcreds.Client{
		HTTP:    &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: cfg.Net.Dialer().DialContext, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second}},
		Captcha: &captchaGate{e: e, next: cfg.Captcha},
		Logf:    e.logf,
	}
	for _, h := range cfg.Link.Hashes {
		e.hashes = append(e.hashes, &hashState{hash: h})
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
	// The first session: a few tries, across TURN servers.
	var first *session.Session
	for attempt := 0; ; attempt++ {
		first, err = e.dial(ctx, attempt*len(e.hashes))
		if err == nil {
			break
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
	e.logf("connected: address %s, MTU %d, %d VK call(s), %d sessions", e.wg.Address, e.wg.MTU, len(e.hashes), e.cfg.Sessions)

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
	return nil
}

// worker keeps session slot i alive.
func (e *Engine) worker(i int, s *session.Session) {
	defer e.workers.Done()
	backoff := time.Second
	for e.ctx.Err() == nil {
		if s == nil {
			var err error
			s, err = e.dial(e.ctx, i)
			if err != nil {
				if e.ctx.Err() != nil {
					return
				}
				if fatal(err) {
					e.fail(err)
					return
				}
				e.noteError(fmt.Sprintf("session %d: %v", i, err))
				if !sleep(e.ctx, jitter(backoff)) {
					return
				}
				backoff = min(backoff*2, 30*time.Second)
				continue
			}
			e.reconnect.Add(1)
		}
		n := len(e.b.list())
		if !e.b.has(s) {
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
		e.b.remove(s)
		s.Close()
		e.rxClosed.Add(s.RxBytes.Load())
		e.txClosed.Add(s.TxBytes.Load())
		if time.Since(s.Started) > time.Minute {
			backoff = time.Second
		}
		s = nil
		if e.ctx.Err() != nil {
			return
		}
		e.notify()
		if !sleep(e.ctx, jitter(backoff)) {
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
			return
		}
		e.b.deliver(buf[:n])
	}
}

// dial opens session slot i: its VK call is i mod len(hashes), its TURN
// server rotates through the servers VK returned.
func (e *Engine) dial(ctx context.Context, i int) (*session.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	hs, g, creds, err := e.creds(ctx, i)
	if err != nil {
		return nil, err
	}
	server := e.cfg.TURNServer
	if server == "" {
		server = creds.Servers[(i/len(e.hashes))%len(creds.Servers)]
	}
	s, err := session.Dial(ctx, session.Params{
		Peer: e.peer, TURNServer: server, Username: creds.Username, Password: creds.Password,
		AEAD: e.aead, Mode: e.cfg.Mode, Net: e.cfg.Net,
		ConnPassword: e.cfg.Link.Password, DeviceID: e.cfg.DeviceID, Generation: e.gen, Worker: i,
		OnReset: e.serverReset,
	})
	var te *session.TURNError
	if errors.As(err, &te) && te.CredentialsRejected() {
		hs.invalidate(g, creds)
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
		return fmt.Errorf("VK credentials: retrying in %s", wait.Round(time.Second))
	}
	return nil
}

func (hs *hashState) get(ctx context.Context, e *Engine, g int) (*vkcreds.Creds, error) {
	cs := hs.slot(g)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.creds != nil && time.Since(cs.creds.Fetched) < vkcreds.Lifetime {
		return cs.creds, nil
	}
	if err := hs.blocked(); err != nil {
		return nil, err
	}
	c, err := e.vk.Fetch(ctx, hs.hash)
	if err != nil {
		var ce *vkcreds.CallError
		var ae *vkcreds.APIError
		hs.mu.Lock()
		switch {
		case errors.As(err, &ce):
			hs.dead = err
			e.logf("VK call %s… is unusable: %v", short(hs.hash), err)
		case errors.Is(err, vkcreds.ErrCaptchaRequired):
			hs.waitUntil = time.Now().Add(60 * time.Second)
		case errors.As(err, &ae) && ae.RateLimited():
			hs.waitUntil = time.Now().Add(30 * time.Second)
		default:
			hs.waitUntil = time.Now().Add(5 * time.Second)
		}
		hs.mu.Unlock()
		return nil, err
	}
	e.logf("VK call %s… group %d: TURN credentials, %d server(s)", short(hs.hash), g+1, len(c.Servers))
	cs.creds = c
	return c, nil
}

func (hs *hashState) invalidate(g int, c *vkcreds.Creds) {
	cs := hs.slot(g)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.creds == c && time.Since(c.Fetched) > 15*time.Second {
		cs.creds = nil
	}
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
		if rx := e.b.rx.Load(); rx != lastRx || len(list) == 0 {
			lastRx, rxAt, txAtRx = rx, time.Now(), e.b.tx.Load()
			continue
		}
		silent := time.Since(rxAt)
		reason := ""
		switch {
		case silent > silentActive && e.b.tx.Load()-txAtRx >= 10:
			reason = fmt.Sprintf("no answer from the server for %s while sending", silent.Round(time.Second))
		case silent > staleRx:
			reason = "no data from the server for 3 minutes"
		}
		if reason == "" {
			continue
		}
		e.noteError(reason + ", reconnecting all sessions")
		for _, s := range list {
			s.Close()
		}
		lastRx, rxAt, txAtRx = e.b.rx.Load(), time.Now(), e.b.tx.Load()
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
	e.mu.Lock()
	st.State, st.LastError, st.Since = e.state, e.lastErr, e.since.Unix()
	e.mu.Unlock()
	if e.captchas.Load() > 0 && st.State != StateFailed && st.State != StateStopped {
		st.State = StateCaptcha
	}
	if e.wg != nil {
		st.Address = e.wg.Address.String()
	}
	return st
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
