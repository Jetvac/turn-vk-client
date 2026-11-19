//go:build linux || android

package mobile

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"

	"github.com/Jetvac/turn-vk-client/core/diag"
	"github.com/Jetvac/turn-vk-client/core/engine"
)

// Ping runs the ping test through the tunnel (about 20 s: call it off the
// main thread) and returns the result as JSON: diag.PingResult and "text",
// the result in a line.
func Ping() string {
	sp.mu.Lock()
	rt := sp.router
	sp.mu.Unlock()
	mu.Lock()
	e := current
	mu.Unlock()
	var r diag.PingResult
	if rt == nil || e == nil || e.State() != engine.StateConnected {
		r.Error = "сначала подключитесь"
	} else {
		dst := netip.MustParseAddrPort(diag.PingTarget)
		// The app's own sockets go around the VPN: through the router.
		dial := func(ctx context.Context) (net.Conn, error) { return rt.DialVPN(ctx, dst) }
		r = diag.PingTCP(e.Context(), dial, diag.PingCount, diag.PingEvery, nil)
		engine.StatsEvent("ping test: %s", r.Text())
	}
	b, _ := json.Marshal(struct {
		diag.PingResult
		Text string `json:"text"`
	}{r, r.Text()})
	return string(b)
}
