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
	"fmt"
	"math/rand/v2"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Jetvac/turn-vk-client/core/redact"
	"github.com/Jetvac/turn-vk-client/core/session"
	"github.com/Jetvac/turn-vk-client/core/wrap"
)

const (
	statsEvery     = time.Minute
	statsQueueMax  = 30 // reports waiting for an acknowledgement
	statsEventsMax = 40 // log lines kept between reports
	statsEventLen  = 240
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
}

var statsQ = struct {
	mu      sync.Mutex
	reports []*statsReport
	events  []statsEvent
	dropped int
}{}

type statsEvent struct {
	T   int64  `json:"t"` // unix ms
	Msg string `json:"m"`
}

// StatsEvent adds a line to the next report (the apps' own events, such
// as the check after connecting).
func StatsEvent(format string, args ...any) {
	noteEvent(fmt.Sprintf(format, args...))
}

func noteEvent(msg string) {
	msg = redact.String(msg)
	if len(msg) > statsEventLen {
		msg = msg[:statsEventLen] + "…"
	}
	statsQ.mu.Lock()
	defer statsQ.mu.Unlock()
	if len(statsQ.events) >= statsEventsMax {
		statsQ.dropped++
		return
	}
	statsQ.events = append(statsQ.events, statsEvent{T: time.Now().UnixMilli(), Msg: msg})
}

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
	t := time.NewTicker(statsEvery)
	defer t.Stop()
	send := time.NewTicker(10 * time.Second)
	defer send.Stop()
	var prevRx, prevTx, prevLost, prevPk, prevRec uint64
	prevQDrop, prevRxDrop, prevGaps := e.b.pacer.dropped.Load(), e.b.dropped.Load(), e.b.gaps()
	prevLowLat := e.b.pacer.inter.Secs.Load()
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
		select {
		case <-e.ctx.Done():
			return
		case <-send.C:
			if e.protocol() != "direct" {
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
		if gap := now.Sub(last) - statsEvery; gap > 5*time.Second {
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
		m.TURN = len(turn)
		e.queueStats(m)
		if e.statsAcked.Load() || unacked < statsNoAck {
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
	statsQ.mu.Unlock()
	head := map[string]any{
		"v": 1, "client": e.cfg.Client, "os": runtime.GOOS + "/" + runtime.GOARCH, "sessions": e.cfg.Sessions,
		"obfs": map[bool]string{true: "video", false: "audio"}[e.cfg.Mode == wrap.Video], "since": e.diag.connectedUnix(), "m": []statsMinute{m},
	}
	if dropped > 0 {
		head["ev_dropped"] = dropped
	}
	var body []byte
	for {
		if len(events) > 0 {
			head["ev"] = events
		} else {
			delete(head, "ev")
		}
		raw, _ := json.Marshal(head)
		body = deflate(raw)
		if len(body) <= session.MaxStats || len(events) == 0 {
			break
		}
		// Too long for one datagram: the oldest lines go.
		cut := max(1, len(events)/4)
		head["ev_dropped"] = toInt(head["ev_dropped"]) + cut
		events = events[cut:]
	}
	if len(body) > session.MaxStats {
		return
	}
	statsQ.mu.Lock()
	statsQ.reports = append(statsQ.reports, &statsReport{id: rand.Uint32() | 1, body: body})
	if len(statsQ.reports) > statsQueueMax {
		statsQ.reports = statsQ.reports[len(statsQ.reports)-statsQueueMax:]
	}
	statsQ.mu.Unlock()
}

func toInt(v any) int {
	n, _ := v.(int)
	return n
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
