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
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/tun"

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
	// Log receives one log line.
	Log(line string)
}

var (
	mu      sync.Mutex
	current *engine.Engine
	captcha = &solver{}
)

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
	e, err := engine.New(engine.Config{
		Link: l, DeviceID: deviceID, Sessions: sessions, Mode: wrap.ParseMode(obfs),
		Net: &netx.Net{
			DNS: netx.DefaultDNS,
			Protect: func(fd uintptr) error {
				if !p.Protect(int(fd)) {
					return errors.New("VpnService.protect failed")
				}
				return nil
			},
		},
		Captcha:  captcha,
		Logf:     func(f string, a ...any) { p.Log(fmt.Sprintf(f, a...)) },
		OnStatus: func(s engine.Status) { b, _ := json.Marshal(s); p.OnStatus(string(b)) },
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
		return dev, err
	})
	if err != nil {
		mu.Lock()
		current = nil
		mu.Unlock()
		return err
	}
	go func() {
		<-e.Done()
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

// NetworkChanged tells the engine the device switched networks.
func NetworkChanged() {
	mu.Lock()
	e := current
	mu.Unlock()
	if e != nil {
		e.Reconnect("the network changed")
	}
}

// SubmitCaptcha passes the success_token VK issued after the user solved
// the captcha.
func SubmitCaptcha(token string) { captcha.answer(token, nil) }

// CancelCaptcha reports that the user closed the captcha.
func CancelCaptcha() { captcha.answer("", errors.New("closed by the user")) }

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
	p := s.p
	s.mu.Unlock()
	if p == nil {
		return "", errors.New("no app to show the captcha")
	}
	p.OnCaptcha(url)
	select {
	case r := <-ch:
		return r.token, r.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (s *solver) answer(token string, err error) {
	s.mu.Lock()
	ch := s.pending
	s.pending = nil
	s.mu.Unlock()
	if ch != nil {
		ch <- result{token, err}
	}
}

func (s *solver) cancel() { s.answer("", errors.New("stopped")) }
