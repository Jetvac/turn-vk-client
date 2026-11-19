//go:build windows

package main

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/Jetvac/turn-vk-client/core/diag"
	"github.com/Jetvac/turn-vk-client/core/engine"
)

var pinging atomic.Bool

// ping runs the ping test through the tunnel (about 20 s) and hands the
// samples and the result to the page.
func (a *app) ping() {
	if !pinging.CompareAndSwap(false, true) {
		return
	}
	defer pinging.Store(false)
	a.mu.Lock()
	rt, e := a.router, a.eng
	a.mu.Unlock()
	if rt == nil || e == nil || e.State() != engine.StateConnected {
		a.eval("onPing", diag.PingResult{Error: "сначала подключитесь"})
		return
	}
	dst := netip.MustParseAddrPort(diag.PingTarget)
	// Through the VPN whatever the split tunneling rules say.
	dial := func(ctx context.Context) (net.Conn, error) { return rt.DialVPN(ctx, dst) }
	r := diag.PingTCP(e.Context(), dial, diag.PingCount, diag.PingEvery, func(i int, ms float64) {
		a.eval("onPingSample", i, ms)
	})
	r.Got = nil
	a.logf("%s", r.Text())
	engine.StatsEvent("ping test: %s", r.Text())
	a.eval("onPing", r)
}
