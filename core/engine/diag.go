package engine

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Diag is what a diagnostic report needs from the engine beyond Status:
// whether WireGuard got through to the server and how traffic went lately.
type Diag struct {
	Connected time.Time `json:"connected"` // when the tunnel came up (zero: not yet)
	// FirstHandshake: how long after Connected the server first answered
	// WireGuard's handshake (0: it has not answered).
	FirstHandshake time.Duration `json:"first_handshake"`
	LastHandshake  time.Time     `json:"last_handshake"`
	// WGRx, WGTx: bytes through the tunnel itself (what programs sent and
	// received), as opposed to Status's bytes on the routes.
	WGRx uint64 `json:"wg_rx"`
	WGTx uint64 `json:"wg_tx"`
	// Samples: one every sampleEvery, the newest last.
	Samples []Sample `json:"samples"`
	// Settings of the tunnel the server sent.
	Address  string   `json:"address"`
	DNS      []string `json:"dns"`
	MTU      int      `json:"mtu"`
	Peer     string   `json:"peer"`  // the server's address
	Calls    int      `json:"calls"` // VK calls in the link
	Protocol string   `json:"protocol"`
}

// Sample is the traffic over one sampleEvery.
type Sample struct {
	At     time.Time `json:"at"`
	Rx     uint64    `json:"rx"`     // tunnel bytes in
	Tx     uint64    `json:"tx"`     // tunnel bytes out
	Routes int       `json:"routes"` // open sessions
	Lost   uint64    `json:"lost"`   // server packets lost on the routes
}

const (
	sampleEvery = 10 * time.Second
	maxSamples  = 90 // 15 minutes
	// noHandshake: with no answer to the handshake for this long after the
	// tunnel came up, the log says so.
	noHandshake = 15 * time.Second
	// staleHandshake: WireGuard re-keys every two minutes while it sends; no
	// handshake for this long, with staleSent bytes sent since anything came
	// back, means the server stopped answering. An idle tunnel sends
	// nothing and does not re-key: a phone asleep overnight logged "the
	// server stopped answering" every few minutes, for no fault.
	staleHandshake = 4 * time.Minute
	staleSent      = 1024
)

// staleWatch follows WireGuard's handshakes for the log.
type staleWatch struct {
	rx, txMark uint64 // WireGuard's bytes in, and out when they last grew
	stale      bool
}

// update takes WireGuard's counters and the handshake's age; it returns
// a line for the log, or "".
func (w *staleWatch) update(rx, tx uint64, age time.Duration) string {
	if rx != w.rx || tx < w.txMark {
		w.rx, w.txMark = rx, tx
	}
	switch {
	case age > staleHandshake && !w.stale && tx-w.txMark >= staleSent:
		w.stale = true
		return fmt.Sprintf("WireGuard: no handshake for %s while sending: the server does not answer", age.Round(time.Second))
	case age <= staleHandshake && w.stale:
		w.stale = false
		return "WireGuard: the server answers again"
	}
	return ""
}

type diagState struct {
	mu        sync.Mutex
	connected time.Time
	first     time.Duration
	last      time.Time
	rx, tx    uint64
	samples   []Sample
}

// wgStats reads the WireGuard device's counters for the (only) peer.
func (e *Engine) wgStats() (rx, tx uint64, hs time.Time, ok bool) {
	if e.dev == nil {
		return 0, 0, time.Time{}, false
	}
	s, err := e.dev.IpcGet()
	if err != nil {
		return 0, 0, time.Time{}, false
	}
	var sec, nsec int64
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, found := strings.Cut(sc.Text(), "=")
		if !found {
			continue
		}
		n, _ := strconv.ParseInt(v, 10, 64)
		switch k {
		case "rx_bytes":
			rx += uint64(n)
		case "tx_bytes":
			tx += uint64(n)
		case "last_handshake_time_sec":
			sec = n
		case "last_handshake_time_nsec":
			nsec = n
		}
	}
	if sec > 0 {
		hs = time.Unix(sec, nsec)
	}
	return rx, tx, hs, true
}

// monitor follows WireGuard after the tunnel comes up: it logs the first
// handshake (or its absence), a summary every minute, and keeps the
// samples for Diag.
func (e *Engine) monitor() {
	d := &e.diag
	d.mu.Lock()
	d.connected = time.Now()
	start := d.connected
	d.mu.Unlock()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var prevRx, prevTx, prevLost uint64
	nextSample := start.Add(sampleEvery)
	var minRx, minTx uint64
	minutes := 0
	warned := false
	var stale staleWatch
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-t.C:
		}
		rx, tx, hs, ok := e.wgStats()
		if !ok || e.ctx.Err() != nil {
			continue
		}
		now := time.Now()
		d.mu.Lock()
		d.rx, d.tx = rx, tx
		first := d.first
		if !hs.IsZero() {
			d.last = hs
			if first == 0 && !hs.Before(start.Add(-time.Second)) {
				d.first = max(hs.Sub(start), time.Millisecond)
			}
		}
		newFirst := first == 0 && d.first != 0
		d.mu.Unlock()
		switch {
		case newFirst:
			e.logf("WireGuard: the server answered the handshake (%s after connecting)", d.first.Round(100*time.Millisecond))
		case d.first == 0 && !warned && now.Sub(start) > noHandshake:
			warned = true
			e.logf("WireGuard: no answer to the handshake for %s; the routes are open but the server does not answer through them (server down, or it does not accept this device)", noHandshake)
		}
		if d.first != 0 && !hs.IsZero() {
			if line := stale.update(rx, tx, now.Sub(hs)); line != "" {
				e.logf("%s", line)
			}
		}
		if now.Before(nextSample) {
			continue
		}
		nextSample = nextSample.Add(sampleEvery)
		list := e.b.list()
		var lost uint64
		for _, s := range list {
			lost += s.RxLost.Load()
		}
		sm := Sample{At: now, Rx: rx - prevRx, Tx: tx - prevTx, Routes: len(list)}
		if lost >= prevLost {
			sm.Lost = lost - prevLost
		}
		prevRx, prevTx, prevLost = rx, tx, lost
		d.mu.Lock()
		d.samples = append(d.samples, sm)
		if len(d.samples) > maxSamples {
			d.samples = append([]Sample(nil), d.samples[len(d.samples)-maxSamples:]...)
		}
		d.mu.Unlock()
		minRx += sm.Rx
		minTx += sm.Tx
		if minutes++; minutes%6 == 0 {
			hsText := "none yet"
			if !hs.IsZero() {
				hsText = now.Sub(hs).Round(time.Second).String() + " ago"
			}
			e.logf("last minute: in %s, out %s through the tunnel, %d/%d routes, handshake %s", bytesText(minRx), bytesText(minTx), len(list), e.cfg.Sessions, hsText)
			minRx, minTx = 0, 0
		}
	}
}

// Diag returns the engine's diagnostics.
func (e *Engine) Diag() Diag {
	d := &e.diag
	d.mu.Lock()
	out := Diag{Connected: d.connected, FirstHandshake: d.first, LastHandshake: d.last, WGRx: d.rx, WGTx: d.tx, Samples: append([]Sample(nil), d.samples...)}
	d.mu.Unlock()
	out.Calls = len(e.hashes)
	out.Protocol = e.protocol()
	if e.peer != nil {
		out.Peer = e.peer.String()
	}
	if e.wg != nil {
		out.Address = e.wg.Address.String()
		out.MTU = e.wg.MTU
		for _, a := range e.wg.DNS {
			out.DNS = append(out.DNS, a.String())
		}
	}
	return out
}

func bytesText(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
