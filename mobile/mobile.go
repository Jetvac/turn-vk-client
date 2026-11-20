//go:build linux || android

// Package mobile is the engine's API for the Android app (gomobile bind).
// Only gomobile-compatible types cross the boundary: strings, ints, bools
// and the Platform interface the app implements.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/Jetvac/captcha-auto"
	"github.com/Jetvac/captcha-auto/profile"

	"github.com/Jetvac/turn-vk-client/core/engine"
	"github.com/Jetvac/turn-vk-client/core/link"
	"github.com/Jetvac/turn-vk-client/core/netx"
	"github.com/Jetvac/turn-vk-client/core/wrap"
)

// Platform is implemented by the app's VpnService.
type Platform interface {
	// Protect excludes a socket from the VPN (VpnService.protect).
	Protect(fd int) bool
	// OpenTun establishes the VPN interface and returns its file
	// descriptor, detached (the engine owns it), or -1.
	OpenTun(address string, prefixLen int, dns string, mtu int) int
	// OnStatus receives the engine status as JSON.
	OnStatus(status string)
	// OnCaptcha asks the user to solve the captcha at url; the app answers
	// with SubmitCaptcha or CancelCaptcha.
	OnCaptcha(url string)
	// OnCaptchaDone: the engine no longer waits for that captcha (answered,
	// cancelled, timed out or stopped). It comes before any next OnCaptcha.
	OnCaptchaDone()
	// Log receives one log line.
	Log(line string)
	// OwnerUID returns the user ID of the app that owns a connection
	// (ConnectivityManager.getConnectionOwnerUid, Android 10+), or -1.
	// proto is 6 (TCP) or 17 (UDP).
	OwnerUID(proto int, srcIP string, srcPort int, dstIP string, dstPort int) int
	// PackagesForUID returns the packages with a user ID, comma-separated.
	PackagesForUID(uid int) string
	// Device returns the battery and power state as JSON (engine.DeviceState),
	// for the statistics; "" when unknown. Called once a minute.
	Device() string
}

var (
	mu      sync.Mutex
	current *engine.Engine
	captcha = &solver{}
	dataDir string
	noStats bool
	client  string
	power   = engine.PowerBalanced
)

// SetPower sets the power mode for the next Start: "saver", "balanced"
// (the default) or "always" (engine.Power*).
func SetPower(mode string) {
	mu.Lock()
	defer mu.Unlock()
	switch mode {
	case engine.PowerSaver, engine.PowerAlways:
		power = mode
	default:
		power = engine.PowerBalanced
	}
}

// SetStats says whether the engine sends the server statistics of the
// connection, and how it names the app in them ("TurnVK 0.5.0 android").
// Call it before Start.
func SetStats(enabled bool, app string) {
	mu.Lock()
	noStats, client = !enabled, app
	mu.Unlock()
}

// SetDataDir sets the app's private directory (Context.filesDir). The
// engine keeps VK guest tokens there, so that restarts of the app do not
// bring up a captcha. Call it before Start.
func SetDataDir(dir string) {
	mu.Lock()
	dataDir = dir
	mu.Unlock()
}

// ValidateLink returns "" for a usable wdtt:// link, else the problem.
func ValidateLink(raw string) string {
	if _, err := link.Parse(raw); err != nil {
		return err.Error()
	}
	return ""
}

// Start connects and returns once the tunnel is up (or with the reason it
// could not be brought up). The engine keeps running in the background
// until Stop.
func Start(rawLink, deviceID string, sessions int, obfs string, p Platform) error {
	l, err := link.Parse(rawLink)
	if err != nil {
		return err
	}
	mu.Lock()
	if current != nil {
		mu.Unlock()
		return errors.New("already running")
	}
	captcha.setPlatform(p)
	vkCache := ""
	if dataDir != "" {
		vkCache = filepath.Join(dataDir, "vk-guests.json")
	}
	protect := func(fd uintptr) error {
		if !p.Protect(int(fd)) {
			return errors.New("VpnService.protect failed")
		}
		return nil
	}
	splitLog = func(s string) { p.Log(s) }
	e, err := engine.New(engine.Config{
		Link: l, DeviceID: deviceID, Sessions: sessions, Mode: wrap.ParseMode(obfs),
		Net: &netx.Net{
			DNS:     netx.DefaultDNS,
			Protect: protect,
		},
		Captcha:  captcha,
		VKCache:  vkCache,
		NoStats:  noStats,
		Client:   client,
		Logf:     func(f string, a ...any) { p.Log(fmt.Sprintf(f, a...)) },
		OnStatus: func(s engine.Status) { b, _ := json.Marshal(s); p.OnStatus(string(b)) },
		// A phone's battery: an idle tunnel lets the radio sleep (unless
		// the user chose to stay always ready).
		Power:  power,
		Device: func() *engine.DeviceState { return parseDevice(p.Device()) },
	})
	if err != nil {
		mu.Unlock()
		return err
	}
	current = e
	mu.Unlock()

	err = e.Start(context.Background(), func(c *engine.WGConfig) (tun.Device, error) {
		dns := make([]string, 0, len(c.DNS))
		for _, a := range c.DNS {
			dns = append(dns, a.String())
		}
		if len(dns) == 0 {
			dns = []string{"1.1.1.1"}
		}
		fd := p.OpenTun(c.Address.Addr().String(), c.Address.Bits(), strings.Join(dns, ","), c.MTU)
		if fd < 0 {
			return nil, errors.New("the VPN interface could not be created")
		}
		dev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
		if err != nil {
			return nil, err
		}
		return wrapTun(dev, c, p, protect), nil
	})
	if err != nil {
		mu.Lock()
		current = nil
		mu.Unlock()
		return err
	}
	go keepListsFresh(e)
	go func() {
		<-e.Done()
		dropRouter()
		mu.Lock()
		if current == e {
			current = nil
		}
		mu.Unlock()
	}()
	return nil
}

// Stop disconnects.
func Stop() {
	mu.Lock()
	e := current
	current = nil
	mu.Unlock()
	captcha.cancel()
	if e != nil {
		e.Stop()
	}
}

// Running reports whether a connection is active.
func Running() bool {
	mu.Lock()
	defer mu.Unlock()
	return current != nil
}

// Status returns the current status as JSON ("" when stopped).
func Status() string {
	mu.Lock()
	e := current
	mu.Unlock()
	if e == nil {
		return ""
	}
	b, _ := json.Marshal(e.Status())
	return string(b)
}

// NetworkChanged tells the engine the device switched networks. The
// platform binds each route's socket to the network it opened on
// (Platform.Protect), so the old routes carry the traffic while new ones
// open on the new network (engine.SwitchNetwork).
func NetworkChanged() {
	if e := engineNow(); e != nil {
		e.SwitchNetwork("the network changed")
	}
}

// NetworkLost tells the engine the device has no network: the routes are
// kept until it is back.
func NetworkLost() {
	if e := engineNow(); e != nil {
		e.NetworkLost()
	}
}

// NetworkBack tells the engine the network it lost is back: the routes
// are checked, not rebuilt.
func NetworkBack() {
	if e := engineNow(); e != nil {
		e.NetworkBack()
	}
}

func engineNow() *engine.Engine {
	mu.Lock()
	defer mu.Unlock()
	return current
}

// SubmitCaptcha passes the success_token VK issued after the user solved
// the captcha.
func SubmitCaptcha(token string) { captcha.answer(token, nil) }

// CancelCaptcha reports that the user closed the captcha.
func CancelCaptcha() { captcha.answer("", errors.New("closed by the user")) }

// SetCaptchaMode switches the engine's captcha handling between manual mode
// (show VK's page and let the user solve it) and auto mode (solve it with the
// captcha-auto solver). mode is "auto" or "manual". It's bound for gomobile,
// so it takes a string rather than a bool (bool can't be a C function
// parameter name). Call it before connecting so the next captcha uses the
// selected mode.
func SetCaptchaMode(mode string) {
	captcha.mu.Lock()
	switch mode {
	case "auto":
		captcha.auto = true
	default:
		captcha.auto = false
	}
	captcha.mu.Unlock()
}

// Address returns the tunnel address once connected, e.g. "10.66.66.7".
func Address() string {
	mu.Lock()
	e := current
	mu.Unlock()
	if e == nil || e.WG() == nil {
		return ""
	}
	return e.WG().Address.Addr().String()
}

var _ = netip.Addr{}

type solver struct {
	mu      sync.Mutex
	p       Platform
	pending chan result
	// auto, when true, solves captchas with the captcha-auto solver instead
	// of showing VK's page to the user.
	auto bool
}

type result struct {
	token string
	err   error
}

func (s *solver) setPlatform(p Platform) {
	s.mu.Lock()
	s.p = p
	s.mu.Unlock()
}

func (s *solver) SolveCaptcha(ctx context.Context, url string) (string, error) {
	ch := make(chan result, 1)
	s.mu.Lock()
	s.pending = ch
	auto := s.auto
	p := s.p
	s.mu.Unlock()
	if p == nil {
		return "", errors.New("no app to show the captcha")
	}
	if auto {
		return s.solveAuto(ctx, url)
	}
	p.OnCaptcha(url)
	defer p.OnCaptchaDone()
	select {
	case r := <-ch:
		return r.token, r.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// solveAuto solves the captcha with the captcha-auto solver and returns the
// success token VK issued. It never returns VK rejection errors.
func (s *solver) solveAuto(ctx context.Context, url string) (string, error) {
	prof := profile.AndroidProfile()
	saved, _ := profile.LoadProfileFromDisk()
	solver := captchaauto.CaptchaSolverFromProfile(prof, saved, 10)
	return solver.SolveCaptcha(ctx, url)
}

func (s *solver) answer(token string, err error) {
	s.mu.Lock()
	ch := s.pending
	auto := s.auto
	p := s.p
	s.pending = nil
	s.mu.Unlock()
	if ch != nil {
		ch <- result{token, err}
	}
	if auto && token != "" && p != nil {
		p.Log("автокапча пройдена")
	}
}

func (s *solver) cancel() { s.answer("", errors.New("stopped")) }

// parseDevice reads Platform.Device's answer (nil: unknown).
func parseDevice(s string) *engine.DeviceState {
	var d engine.DeviceState
	if s == "" || json.Unmarshal([]byte(s), &d) != nil {
		return nil
	}
	return &d
}
