package engine

// Statistics for the server (TurnVK servers only): once a minute the
// engine sends the server a short report of how the connection went over
// the last minute, through its own routes (VK's TURN servers, inside the
// RTP wrap like everything else). The server's owner analyses them to
// tune the transport. A report holds numbers and the engine's log lines
// with secrets taken out, never addresses of sites or traffic contents.
//
// Reports wait in a small queue until the server acknowledges them, so a
// minute without working routes is reported later. The queue and the
// events belong to the process, not to one connection: what went wrong
// with a connection that failed goes out with the next one that works.

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"math/rand/v2"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Jetvac/turn-vk-client/core/session"
	"github.com/Jetvac/turn-vk-client/core/wrap"
)

const (
	statsEvery = time.Minute
	// statsQueueMax: reports waiting for an acknowledgement; the oldest go
	// beyond it, and the next report says which minutes were lost.
	statsQueueMax  = 60
	statsEventsMax = 60 // kinds of log lines kept between reports (events.go)
	statsEventLen  = 240
	// statsParts: a minute's report with many events goes out in up to
	// this many datagrams (the first holds the numbers).
	statsParts     = 3
	statsSendBatch = 3 // reports sent per tick
	// statsNoAck: the server acknowledged none of this many sends: it does
	// not collect statistics (an older version, or one not restarted after
	// an update); from then on try only every statsRetry.
	statsNoAck = 6
	statsRetry = 10 * time.Minute
)

type statsReport struct {
	id   uint32
	body []byte
	sent int
	t    int64 // the minute's end, unix ms
	part int   // 0: the minute's numbers; more: its further events
}

// statsLost: reports the queue let go before the server had them.
type statsLost struct {
	N    int   `json:"n"`
	From int64 `json:"from"` // first lost minute, unix ms
	To   int64 `json:"to"`   // last
}

var statsQ = struct {
	mu      sync.Mutex
	reports []*statsReport
	events  []statsEvent
	dropped int
	// seq numbers the minutes of this run of the app (run): a gap in seq
	// means reports were lost, a gap in time without one that the engine
	// did not run (asleep, or not connected).
	seq  int
	run  uint32
	lost statsLost
	// down: since when and why there has been no connection (downtime.go).
	down     time.Time
	downWhy  string
	downSeen bool
}{run: rand.Uint32() | 1}

// statsMinute is one minute of the connection.
type statsMinute struct {
	T          int64   `json:"t"`             // end of the minute, unix ms
	State      string  `json:"state"`         // engine state at the end
	Rx         uint64  `json:"rx"`            // tunnel bytes in
	Tx         uint64  `json:"tx"`            // tunnel bytes out
	Routes     int     `json:"routes"`        // open
	Fresh      int     `json:"fresh"`         // heard from in the last seconds
	Target     int     `json:"target"`        // routes wanted
	RTT        int     `json:"rtt"`           // ms, average over routes
	RTTMax     int     `json:"rtt_max"`       // ms, worst route
	Lost       uint64  `json:"lost"`          // server packets lost on the routes
	RxPk       uint64  `json:"rx_pk"`         // server packets received on the routes
	UpRate     int     `json:"up_rate"`       // B/s, sum of the routes' upload pacing
	UpLoss     float64 `json:"up_loss"`       // average upload loss the server reports
	Reconnects uint64  `json:"reconnects"`    // routes re-opened this minute
	HSAge      int     `json:"hs_age"`        // s since WireGuard's last handshake (-1: none)
	Captcha    bool    `json:"captcha"`       // VK waits for a captcha
	TURN       int     `json:"turn"`          // distinct VK TURN servers in use
	Calls      int     `json:"calls"`         // VK calls in the link
	Slept      bool    `json:"slept"`         // the device slept during the minute
	Gap        int     `json:"gap,omitempty"` // s the engine did not run (sleep)
	// Spikes: the routes' ping round trips (all pongs of the minute), how
	// long packets the reorder buffer held waited, how long small packets
	// (games, pings, ACKs) waited in the upload pacer; packets the pacer
	// dropped as too old, received packets dropped because WireGuard did
	// not keep up, and gaps the reorder buffer gave up on (lost packets).
	Ping   *session.Lat `json:"ping,omitempty"`
	Hold   *session.Lat `json:"hold,omitempty"`
	Queue  *session.Lat `json:"queue,omitempty"`
	QDrop  uint64       `json:"q_drop,omitempty"`
	RxDrop uint64       `json:"rx_drop,omitempty"`
	Gaps   uint64       `json:"gaps,omitempty"`
	// LowLat: seconds the upload pacer kept queues short for interactive
	// traffic (games, calls).
	LowLat uint64 `json:"low_lat,omitempty"`
	// Quiet: seconds in idle mode; Light: seconds on the light tier of
	// routes on demand (idle.go).
	Quiet uint64 `json:"quiet,omitempty"`
	Light uint64 `json:"light,omitempty"`
	// Battery: times the device woke from sleep, CPU time the app used
	// (ms), and the battery and power state at the end (Config.Device).
	Wakes uint64       `json:"wakes,omitempty"`
	CPU   int64        `json:"cpu_ms,omitempty"`
	Dev   *DeviceState `json:"dev,omitempty"`
	// Direct: split tunneling's direct path at the end of the minute
	// (Config.Direct), with the direct UDP sends that failed during it.
	Direct *directMinute `json:"direct,omitempty"`
	// Net: the physical network at the end of the minute (Config.Network),
	// with the changes during it.
	Net *NetState `json:"net,omitempty"`
}

type directMinute struct {
	Flows    int    `json:"flows"`
	UDPSocks int    `json:"udp_socks"`
	UDPErr   uint64 `json:"udp_err,omitempty"`
}

// statsAck is called by the sessions' read loops.
func (e *Engine) statsAck(id uint32) {
	e.statsAcked.Store(true)
	statsQ.mu.Lock()
	defer statsQ.mu.Unlock()
	for i, r := range statsQ.reports {
		if r.id == id {
			statsQ.reports = append(statsQ.reports[:i], statsQ.reports[i+1:]...)
			return
		}
	}
}

// statsLoop runs while connected.
func (e *Engine) statsLoop() {
	if e.cfg.NoStats {
		return
	}
	if line, ok := takeDown(time.Now()); ok {
		e.logf("%s", line)
	}
	t := time.NewTicker(statsEvery)
	defer t.Stop()
	send := time.NewTicker(10 * time.Second)
	defer send.Stop()
	var prevRx, prevTx, prevLost, prevPk, prevRec uint64
	prevQDrop, prevRxDrop, prevGaps := e.b.pacer.dropped.Load(), e.b.dropped.Load(), e.b.gaps()
	prevLowLat := e.b.pacer.inter.Secs.Load()
	prevQuiet, prevLight := e.idle.secs.Load(), e.idle.lightSecs.Load()
	prevWakes, prevCPU := e.wakes.Load(), processCPU()
	prevNetChg := e.netChg.Load()
	var prevDirErr uint64
	if e.cfg.Direct != nil {
		prevDirErr = e.cfg.Direct().UDPErr
	}
	e.rtts.Take()
	e.b.holds.Take()
	e.b.qwait.Take()
	if rx, tx, _, ok := e.wgStats(); ok {
		prevRx, prevTx = rx, tx
	}
	prevRec = e.reconnect.Load()
	for _, s := range e.b.list() {
		prevLost += s.RxLost.Load()
		prevPk += s.RxPackets.Load()
	}
	last := time.Now()
	unacked := 0
	var probed time.Time
	for {
		// While idle, reports go out with the routes' ping bursts only, so
		// that they wake the radio no extra time.
		burst := e.quiet.Woken()
		select {
		case <-e.ctx.Done():
			return
		case <-burst:
			if !e.quiet.On() || e.protocol() != "direct" {
				continue
			}
			if !e.statsAcked.Load() && unacked >= statsNoAck {
				if time.Since(probed) < statsRetry {
					continue
				}
				probed = time.Now()
			}
			unacked += e.sendStats()
			continue
		case <-send.C:
			if e.protocol() != "direct" || e.quiet.On() {
				continue
			}
			if !e.statsAcked.Load() && unacked >= statsNoAck {
				if time.Since(probed) < statsRetry {
					continue
				}
				probed = time.Now()
			}
			unacked += e.sendStats()
			continue
		case <-t.C:
		}
		if e.protocol() != "direct" {
			continue
		}
		now := time.Now()
		m := statsMinute{T: now.UnixMilli(), State: e.State(), Target: e.cfg.Sessions, Calls: len(e.hashes), HSAge: -1}
		// Real time: the ticker runs on the monotonic clock, which stands
		// still while the device sleeps, so a dozing phone's "minute" may
		// span many.
		if gap := now.Round(0).Sub(last.Round(0)) - statsEvery; gap > 5*time.Second {
			m.Slept, m.Gap = true, int(gap/time.Second)
		}
		if w := e.wokeAt.Load(); w > last.UnixNano() {
			m.Slept = true
		}
		last = now
		rx, tx, hs, _ := e.wgStats()
		m.Rx, m.Tx = sub0(rx, prevRx), sub0(tx, prevTx)
		prevRx, prevTx = rx, tx
		if !hs.IsZero() {
			m.HSAge = int(now.Sub(hs) / time.Second)
		}
		list := e.b.list()
		m.Routes = len(list)
		var lost, pk uint64
		var rttSum, rttN int64
		var lossSum float64
		var lossN int
		turn := map[string]bool{}
		for _, s := range list {
			lost += s.RxLost.Load()
			pk += s.RxPackets.Load()
			turn[s.Server] = true
			if s.Fresh(now) {
				m.Fresh++
			}
			if r := s.RTT.Load(); r > 0 {
				rttSum += r
				rttN++
				m.RTTMax = max(m.RTTMax, int(r/int64(time.Millisecond)))
			}
			if s.Pace.HasFeedback() {
				rate, loss, _ := s.Pace.State()
				m.UpRate += int(rate)
				lossSum += loss
				lossN++
			}
		}
		// Routes that closed take their counters with them.
		m.Lost, m.RxPk = sub0(lost, prevLost), sub0(pk, prevPk)
		prevLost, prevPk = lost, pk
		if rttN > 0 {
			m.RTT = int(rttSum / rttN / int64(time.Millisecond))
		}
		if lossN > 0 {
			m.UpLoss = float64(int(lossSum/float64(lossN)*10000)) / 10000
		}
		rec := e.reconnect.Load()
		m.Reconnects, prevRec = rec-prevRec, rec
		m.Captcha = e.captchas.Load() > 0
		m.Ping, m.Hold, m.Queue = e.rtts.Take(), e.b.holds.Take(), e.b.qwait.Take()
		qd, rd, gp := e.b.pacer.dropped.Load(), e.b.dropped.Load(), e.b.gaps()
		m.QDrop, m.RxDrop, m.Gaps = sub0(qd, prevQDrop), sub0(rd, prevRxDrop), sub0(gp, prevGaps)
		prevQDrop, prevRxDrop, prevGaps = qd, rd, gp
		ll := e.b.pacer.inter.Secs.Load()
		m.LowLat, prevLowLat = sub0(ll, prevLowLat), ll
		qs, ls := e.idle.secs.Load(), e.idle.lightSecs.Load()
		m.Quiet, prevQuiet = sub0(qs, prevQuiet), qs
		m.Light, prevLight = sub0(ls, prevLight), ls
		wk, cpu := e.wakes.Load(), processCPU()
		m.Wakes, prevWakes = sub0(wk, prevWakes), wk
		m.CPU, prevCPU = int64(max(0, cpu-prevCPU)/time.Millisecond), cpu
		if e.cfg.Device != nil {
			m.Dev = e.cfg.Device()
		}
		if e.cfg.Direct != nil {
			d := e.cfg.Direct()
			if d.Flows > 0 || d.UDPSocks > 0 || d.UDPErr != prevDirErr {
				m.Direct = &directMinute{Flows: d.Flows, UDPSocks: d.UDPSocks, UDPErr: sub0(d.UDPErr, prevDirErr)}
			}
			prevDirErr = d.UDPErr
		}
		chg := e.netChg.Load()
		if e.cfg.Network != nil {
			m.Net = e.cfg.Network()
		}
		if chg != prevNetChg {
			if m.Net == nil {
				m.Net = &NetState{}
			}
			m.Net.Changes = chg - prevNetChg
		}
		prevNetChg = chg
		m.TURN = len(turn)
		e.queueStats(m)
		if (e.statsAcked.Load() || unacked < statsNoAck) && !e.quiet.On() {
			unacked += e.sendStats()
		}
	}
}

// sub0 is a - b, or 0 when the counter went back (routes closed).
func sub0(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

// queueStats builds the minute's report with the events since the last.
func (e *Engine) queueStats(m statsMinute) {
	statsQ.mu.Lock()
	events, dropped := statsQ.events, statsQ.dropped
	statsQ.events, statsQ.dropped = nil, 0
	statsQ.seq++
	seq, run, lost := statsQ.seq, statsQ.run, statsQ.lost
	statsQ.lost = statsLost{}
	statsQ.mu.Unlock()
	head := map[string]any{
		"v": 1, "client": e.cfg.Client, "os": runtime.GOOS + "/" + runtime.GOARCH, "sessions": e.cfg.Sessions,
		"obfs": map[bool]string{true: "video", false: "audio"}[e.cfg.Mode == wrap.Video], "since": e.diag.connectedUnix(), "m": []statsMinute{m},
		"seq": seq, "run": run,
	}
	if e.cfg.Power != "" {
		head["power"] = e.cfg.Power
	}
	if lost.N > 0 {
		head["lost"] = lost
	}
	// Further parts: the events that did not fit the first, tied to it by
	// run and seq.
	more := map[string]any{"v": 1, "client": e.cfg.Client, "seq": seq, "run": run}
	bodies := packEvents(events, func(part int, ev []statsEvent, left int) []byte {
		h := head
		if part > 0 {
			h = more
			h["part"] = part
		}
		if len(ev) > 0 {
			h["ev"] = ev
		} else {
			delete(h, "ev")
		}
		if part == 0 && dropped+left > 0 {
			h["ev_dropped"] = dropped + left
		} else {
			delete(h, "ev_dropped")
		}
		raw, _ := json.Marshal(h)
		return deflate(raw)
	})
	if len(bodies) == 0 {
		return
	}
	statsQ.mu.Lock()
	for i, b := range bodies {
		statsQ.reports = append(statsQ.reports, &statsReport{id: rand.Uint32() | 1, body: b, t: m.T, part: i})
	}
	if n := len(statsQ.reports) - statsQueueMax; n > 0 {
		for _, r := range statsQ.reports[:n] {
			if r.part != 0 {
				continue
			}
			l := &statsQ.lost
			if l.N == 0 {
				l.From = r.t
			}
			l.N++
			l.To = r.t
		}
		statsQ.reports = statsQ.reports[n:]
	}
	statsQ.mu.Unlock()
}

// packEvents spreads the events over at most statsParts datagrams, built
// by enc (part 0 holds the minute's numbers; left: events left out). What
// does not fit is left out, the least important and oldest first.
func packEvents(events []statsEvent, enc func(part int, ev []statsEvent, left int) []byte) [][]byte {
	left := 0
	for {
		var out [][]byte
		var cur []statsEvent
		fits := true
		for _, ev := range events {
			next := append(cur[:len(cur):len(cur)], ev)
			if len(cur) == 0 || len(enc(len(out), next, left)) <= session.MaxStats {
				cur = next
				continue
			}
			out = append(out, enc(len(out), cur, left))
			cur = []statsEvent{ev}
		}
		out = append(out, enc(len(out), cur, left))
		for _, b := range out {
			fits = fits && len(b) <= session.MaxStats
		}
		if fits && len(out) <= statsParts {
			return out
		}
		if len(events) == 0 {
			return nil
		}
		k := max(1, len(events)/8)
		events = dropLeast(events, k)
		left += k
	}
}

func deflate(b []byte) []byte {
	var buf bytes.Buffer
	zw, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	zw.Write(b)
	zw.Close()
	return buf.Bytes()
}

// sendStats sends the oldest waiting reports, each on a fresh route; it
// returns how many went out.
func (e *Engine) sendStats() int {
	now := time.Now()
	var routes []*session.Session
	for _, s := range e.b.list() {
		if s.Direct() && s.Fresh(now) {
			routes = append(routes, s)
		}
	}
	if len(routes) == 0 {
		return 0
	}
	statsQ.mu.Lock()
	var batch []*statsReport
	for _, r := range statsQ.reports {
		if len(batch) == statsSendBatch {
			break
		}
		r.sent++
		batch = append(batch, r)
	}
	statsQ.mu.Unlock()
	n := 0
	for i, r := range batch {
		if routes[(i+rand.IntN(len(routes)))%len(routes)].SendStats(r.id, r.body) == nil {
			n++
		}
	}
	return n
}

// connectedUnix: when the tunnel came up (unix s, 0 before).
func (d *diagState) connectedUnix() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.connected.IsZero() {
		return 0
	}
	return d.connected.Unix()
}

// statsLogLine decides whether an engine log line goes into the report:
// the minute summaries are in the numbers already.
func statsLogLine(line string) bool {
	return !strings.HasPrefix(line, "last minute:")
}
