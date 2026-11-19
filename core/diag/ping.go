package diag

import (
	"context"
	"fmt"
	"math"
	"net"
	"slices"
	"time"
)

// Ping test: how a game would feel through the VPN. A TCP connection's
// opening (SYN, SYN-ACK) takes one round trip through the tunnel, the
// server and on to the target, so connecting over and over measures the
// round trip a few times a second, spikes included.

const (
	PingTarget = "1.1.1.1:443" // Cloudflare: close to nearly any server
	PingCount  = 80
	PingEvery  = 250 * time.Millisecond
	pingLimit  = 2 * time.Second // slower counts as lost
)

// PingResult sums a ping test up (ms).
type PingResult struct {
	Via    string    `json:"via"` // what was measured
	Sent   int       `json:"sent"`
	Lost   int       `json:"lost"`
	Min    float64   `json:"min"`
	P50    float64   `json:"p50"`
	P95    float64   `json:"p95"`
	Max    float64   `json:"max"`
	Jitter float64   `json:"jitter"` // average change from one sample to the next
	Spikes int       `json:"spikes"` // samples over the median + 50 ms
	Error  string    `json:"error,omitempty"`
	Got    []float64 `json:"got,omitempty"` // the samples in order, -1: lost
}

// PingTCP measures n round trips, every apart, by opening TCP connections
// with dial (which must go through the tunnel). progress, if set, gets
// each sample as it comes (-1: lost).
func PingTCP(ctx context.Context, dial func(context.Context) (net.Conn, error), n int, every time.Duration, progress func(i int, ms float64)) PingResult {
	r := PingResult{Via: "TCP " + PingTarget + " через VPN"}
	t := time.NewTicker(every)
	defer t.Stop()
	for i := 0; i < n; i++ {
		c, cancel := context.WithTimeout(ctx, pingLimit)
		start := time.Now()
		conn, err := dial(c)
		took := time.Since(start)
		cancel()
		ms := -1.0
		if err == nil {
			conn.Close()
			ms = float64(took.Microseconds()) / 1000
		} else if ctx.Err() != nil {
			break
		} else if r.Error == "" {
			r.Error = err.Error()
		}
		r.Got = append(r.Got, ms)
		if progress != nil {
			progress(i, ms)
		}
		select {
		case <-ctx.Done():
		case <-t.C:
		}
		if ctx.Err() != nil {
			break
		}
	}
	r.Sum()
	return r
}

// Sum fills the figures in from Got.
func (r *PingResult) Sum() {
	r.Sent, r.Lost = len(r.Got), 0
	var ok []float64
	prev, jsum, jn := -1.0, 0.0, 0
	for _, v := range r.Got {
		if v < 0 {
			r.Lost++
			continue
		}
		ok = append(ok, v)
		if prev >= 0 {
			jsum += math.Abs(v - prev)
			jn++
		}
		prev = v
	}
	if len(ok) == 0 {
		return
	}
	s := slices.Clone(ok)
	slices.Sort(s)
	at := func(q float64) float64 { return s[min(len(s)-1, int(math.Ceil(q*float64(len(s))))-1)] }
	r.Min, r.P50, r.P95, r.Max = round1(s[0]), round1(at(0.5)), round1(at(0.95)), round1(s[len(s)-1])
	if jn > 0 {
		r.Jitter = round1(jsum / float64(jn))
	}
	for _, v := range ok {
		if v > r.P50+50 {
			r.Spikes++
		}
	}
}

// Text is the result in a line for people.
func (r PingResult) Text() string {
	if r.Sent == 0 || r.Sent == r.Lost {
		e := r.Error
		if e == "" {
			e = "нет ответов"
		}
		return fmt.Sprintf("Пинг (%s): не удалось — %s", r.Via, e)
	}
	return fmt.Sprintf("Пинг (%s): %d замеров, медиана %s мс, 95 %% — %s мс, лучший %s, худший %s мс, разброс %s мс, всплесков %d, потеряно %d",
		r.Via, r.Sent, num(r.P50), num(r.P95), num(r.Min), num(r.Max), num(r.Jitter), r.Spikes, r.Lost)
}

func num(v float64) string {
	if v >= 10 {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.1f", v)
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
