package engine

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun/v4"

	"github.com/Jetvac/turn-vk-client/core/netx"
)

// When VK hands out TURN servers, each is pinged directly (a STUN binding
// request: no allocation, no credentials), so that routes avoid a relay
// that is far slower from here from the start, instead of opening on it
// and being moved later (each move costs an allocation; the stats showed
// a relay answering in 151 ms while the best answered in 34).
const (
	probeTries   = 3
	probeTimeout = time.Second
)

// probeRelays pings the servers not probed lately, in the background.
func (e *Engine) probeRelays(servers []string) {
	if e.cfg.NoRelayScoring || e.cfg.TURNServer != "" || len(servers) < 2 {
		return
	}
	now := time.Now()
	var todo []string
	e.probeMu.Lock()
	for _, sv := range servers {
		if !e.relays.seeded(sv, now) && !e.relayProbing[sv] {
			if e.relayProbing == nil {
				e.relayProbing = map[string]bool{}
			}
			e.relayProbing[sv] = true
			todo = append(todo, sv)
		}
	}
	e.probeMu.Unlock()
	if len(todo) == 0 {
		return
	}
	go func() {
		var mu sync.Mutex
		var got []string
		var wg sync.WaitGroup
		for _, sv := range todo {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rtt, err := stunRTT(e.ctx, e.cfg.Net, sv)
				e.probeMu.Lock()
				delete(e.relayProbing, sv)
				e.probeMu.Unlock()
				if err != nil {
					return
				}
				e.relays.noteSeed(sv, rtt, time.Now())
				mu.Lock()
				got = append(got, sv+" "+rtt.Round(time.Millisecond).String())
				mu.Unlock()
			}()
		}
		wg.Wait()
		if len(got) > 0 {
			sort.Strings(got)
			e.logf("TURN servers answer a probe in: %s", strings.Join(got, ", "))
		}
	}()
}

// stunRTT is the best round trip of a few STUN binding requests to server.
func stunRTT(ctx context.Context, n *netx.Net, server string) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTries*probeTimeout+time.Second)
	defer cancel()
	addr, err := n.ResolveUDP(ctx, server)
	if err != nil {
		return 0, err
	}
	c, err := n.ListenUDP(ctx)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	best := time.Duration(0)
	buf := make([]byte, 1500)
	for try := 0; try < probeTries && ctx.Err() == nil; try++ {
		req, err := stun.Build(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
		if err != nil {
			return 0, err
		}
		start := time.Now()
		if _, err := c.WriteToUDP(req.Raw, addr); err != nil {
			return 0, err
		}
		_ = c.SetReadDeadline(start.Add(probeTimeout))
		for {
			k, _, err := c.ReadFromUDP(buf)
			if err != nil {
				break // timeout: the next try
			}
			var res stun.Message
			res.Raw = append(res.Raw[:0], buf[:k]...)
			if res.Decode() != nil || res.TransactionID != req.TransactionID {
				continue
			}
			if d := time.Since(start); best == 0 || d < best {
				best = d
			}
			break
		}
	}
	if best == 0 {
		return 0, errors.New("no answer")
	}
	return best, nil
}
