package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Thresholds for a stretch that went badly.
const (
	lossBad  = 2.0 // % of the server's packets lost on the routes
	slowerBy = 20  // ms of ping over the device's usual
)

// routine: events of the normal course of things (as core/engine/events.go).
var routine = []string{
	"idle: ", "traffic again", "TURN credentials", "answer a probe", "joining as new guest",
	"moves to guest", "ping test:", "handshake (after sleep)", "the server answers again",
	"light traffic:", "busy: back to",
}

func isRoutine(msg string) bool {
	for _, s := range routine {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return idleHandshake(msg)
}

// idleHandshake: the line clients up to 0.9.2 logged whenever WireGuard had
// not re-keyed for four minutes, which an idle tunnel never does (a phone
// asleep overnight logged it every few minutes, for no fault). Newer ones
// log it only "while sending", and then it is trouble.
func idleHandshake(msg string) bool {
	return strings.HasPrefix(msg, "WireGuard: no handshake for") && strings.Contains(msg, "the server stopped answering")
}

func isMark(msg string) bool { return strings.HasPrefix(msg, "user mark:") }

// trouble: events that mean the connection had a problem.
var trouble = []string{
	"re-keying", "reconnecting", "stopped answering", "silent for", "loses ", "no network",
	"stopped:", "failed", "no answer", "without a connection", "does not answer",
}

func isTrouble(msg string) bool {
	if idleHandshake(msg) {
		return false
	}
	for _, s := range trouble {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// stall: the tunnel got no data while its routes answered: TurnVK's own
// fault, not the network's.
func isStall(msg string) bool { return strings.Contains(msg, "every path answers") }

// agg: minutes of one device taken together.
type agg struct {
	n           int
	rttSum      int
	rttN        int
	p95         float64
	lost, pk    uint64
	quiet       uint64
	light       uint64 // seconds on the light tier (routes on demand)
	slept       bool
	reconnects  uint64
	fresh, want int // the worst minute's routes answering / wanted
	notUp       int // minutes not connected
	rx, tx      uint64
	net         *netState
	netChanges  int
	// Active minutes only (not idle, not asleep): the phone's radio and
	// the routes kept for idle make the rest's ping and loss mean little.
	active     int
	aRTT, aRTN int
	aLost, aPk uint64
}

// isActive: a minute whose ping and loss tell how the network did.
func isActive(m *minute) bool { return m.Quiet < 30 && !m.Slept && m.State == "connected" }

func (g *agg) add(m *minute) {
	if g.n == 0 || m.Fresh*max(g.want, 1) < g.fresh*max(m.Target, 1) {
		g.fresh, g.want = m.Fresh, m.Target
	}
	g.n++
	if m.RTT > 0 {
		g.rttSum += m.RTT
		g.rttN++
	}
	if m.Ping != nil {
		g.p95 = max(g.p95, m.Ping.P95)
	}
	g.lost += m.Lost
	g.pk += m.RxPk
	if isActive(m) {
		g.active++
		g.aLost += m.Lost
		g.aPk += m.RxPk
		if m.RTT > 0 {
			g.aRTT += m.RTT
			g.aRTN++
		}
	}
	g.quiet += m.Quiet
	g.light += m.Light
	g.slept = g.slept || m.Slept
	g.reconnects += m.Reconnects
	if m.State != "connected" {
		g.notUp++
	}
	g.rx += m.Rx
	g.tx += m.Tx
	if m.Net != nil {
		if m.Net.Kind != "" {
			g.net = m.Net
		}
		g.netChanges += m.Net.Changes
	}
}

func (g *agg) rtt() int {
	if g.rttN == 0 {
		return 0
	}
	return g.rttSum / g.rttN
}

// loss: % of the server's packets lost; -1 with too few to tell.
func (g *agg) loss() float64 {
	if g.pk+g.lost < 200 {
		return -1
	}
	return 100 * float64(g.lost) / float64(g.pk+g.lost)
}

// activeRTT, activeLoss: as rtt and loss, over active minutes only (0,
// -1 without them).
func (g *agg) activeRTT() int {
	if g.aRTN == 0 {
		return 0
	}
	return g.aRTT / g.aRTN
}

func (g *agg) activeLoss() float64 {
	if g.aPk+g.aLost < 200 {
		return -1
	}
	return 100 * float64(g.aLost) / float64(g.aPk+g.aLost)
}

// weak: the signal of the device's network is poor.
func (g *agg) weak() string {
	n := g.net
	if n == nil {
		return ""
	}
	switch n.Kind {
	case "wifi":
		if (n.RSSI != 0 && n.RSSI <= -75) || (n.Q != 0 && n.Q < 40) {
			return "weak Wi-Fi (" + netText(n) + ")"
		}
	case "cell":
		if (n.Bars != nil && *n.Bars <= 1) || (n.RSSI != 0 && n.RSSI <= -110) {
			return "weak mobile signal (" + netText(n) + ")"
		}
	}
	return ""
}

func netText(n *netState) string {
	if n == nil || n.Kind == "" {
		return ""
	}
	var p []string
	kind := map[string]string{"wifi": "Wi-Fi", "cell": "mobile", "eth": "wired", "none": "no network"}[n.Kind]
	if kind == "" {
		kind = n.Kind
	}
	if n.Cell != "" {
		kind += " " + strings.ToUpper(n.Cell)
	}
	p = append(p, kind)
	if n.RSSI != 0 {
		p = append(p, fmt.Sprintf("%d dBm", n.RSSI))
	}
	if n.Bars != nil {
		p = append(p, fmt.Sprintf("%d/4", *n.Bars))
	}
	if n.Q != 0 {
		p = append(p, fmt.Sprintf("%d%%", n.Q))
	}
	if n.MHz != 0 {
		p = append(p, fmt.Sprintf("%.1f GHz", float64(n.MHz)/1000))
	}
	if n.Mbps != 0 {
		p = append(p, fmt.Sprintf("%d Mbit/s", n.Mbps))
	}
	return strings.Join(p, ", ")
}

// usual: the device's typical ping, the median of its connected minutes.
func usual(mins []*minute) int {
	var r []int
	for _, m := range mins {
		if m.RTT > 0 && isActive(m) {
			r = append(r, m.RTT)
		}
	}
	if len(r) == 0 {
		return 0
	}
	sort.Ints(r)
	return r[len(r)/2]
}

// others: the rest of the devices over the same stretch.
type others struct {
	n      int     // devices with minutes in it
	slower int     // ms the median device was over its usual ping
	loss   float64 // pooled, -1: too few packets
}

func (o others) String() string {
	if o.n == 0 {
		return "—"
	}
	l := "?"
	if o.loss >= 0 {
		l = fmt.Sprintf("%.1f%%", o.loss)
	}
	return fmt.Sprintf("%+d ms %s (%d)", o.slower, l, o.n)
}

// compare looks at the other devices between from and to.
func compare(a *archive, self *device, base map[string]int, from, to time.Time) others {
	var o others
	var lost, pk uint64
	var slower []int
	for _, d := range a.devs {
		if d == self {
			continue
		}
		var g agg
		for _, m := range between(d.mins, from, to) {
			g.add(m)
		}
		if g.n == 0 {
			continue
		}
		if g.active == 0 {
			continue
		}
		o.n++
		lost += g.aLost
		pk += g.aPk
		if r := g.activeRTT(); r > 0 && base[d.id] > 0 {
			slower = append(slower, r-base[d.id])
		}
	}
	o.loss = -1
	if pk+lost >= 200 {
		o.loss = 100 * float64(lost) / float64(pk+lost)
	}
	if len(slower) > 0 {
		sort.Ints(slower)
		o.slower = slower[len(slower)/2]
	}
	return o
}

func between[T interface{ when() time.Time }](xs []T, from, to time.Time) []T {
	i := sort.Search(len(xs), func(i int) bool { return !xs[i].when().Before(from) })
	j := sort.Search(len(xs), func(i int) bool { return !xs[i].when().Before(to) })
	return xs[i:j]
}

func (m *minute) when() time.Time { return m.at }
func (e *event) when() time.Time  { return e.at }

// verdict says whose side a stretch's trouble was on ("" when it went
// well).
func verdict(g *agg, usualRTT int, evs []*event, o others) string {
	lossy := g.activeLoss() >= lossBad
	slow := usualRTT > 0 && g.activeRTT() > 0 && g.activeRTT() >= usualRTT+slowerBy
	stalls, troubles := 0, 0
	for _, e := range evs {
		if isStall(e.M) {
			stalls += max(e.N, 1)
		}
		if isTrouble(e.M) {
			troubles += max(e.N, 1)
		}
	}
	if !lossy && !slow && troubles == 0 && g.notUp == 0 {
		return ""
	}
	// Everyone: the others had each of this device's problems too.
	shared := o.n > 0 && (!lossy || o.loss >= lossBad) && (!slow || o.slower >= slowerBy)
	switch {
	case shared && (lossy || slow):
		return "everyone at once: the server or VK, not this device"
	case stalls > 0 && !lossy && !slow:
		return "TurnVK on this device: the tunnel stalled while its routes answered"
	case lossy || slow:
		if w := g.weak(); w != "" {
			return "this device's network: " + w
		}
		if o.n > 0 {
			return "this device's network or ISP: only this device was affected"
		}
		return "this device's network or ISP (no other devices to compare)"
	case g.notUp > 0:
		return "not connected"
	}
	return "TurnVK replaced routes; the connection itself was fine"
}
