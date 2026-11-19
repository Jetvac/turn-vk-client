package session

import (
	"math"
	"sync/atomic"
	"time"
)

// Hist counts durations (round trips, waits) for percentiles, without
// locks: 0.1 ms steps up to 10 ms, 1 ms up to 100 ms, 10 ms up to 1 s,
// 100 ms up to 10 s. Take reads and empties it.
type Hist struct {
	b   [histBuckets]atomic.Uint32
	max atomic.Int64 // ns
}

const histBuckets = 100 + 90 + 90 + 90 + 1

func histBucket(d time.Duration) int {
	us := d.Microseconds()
	switch {
	case us < 0:
		return 0
	case us < 10_000:
		return int(us / 100)
	case us < 100_000:
		return 100 + int((us-10_000)/1000)
	case us < 1_000_000:
		return 190 + int((us-100_000)/10_000)
	case us < 10_000_000:
		return 280 + int((us-1_000_000)/100_000)
	}
	return histBuckets - 1
}

// histUpper is the upper edge of bucket i, ms.
func histUpper(i int) float64 {
	switch {
	case i < 100:
		return float64(i+1) / 10
	case i < 190:
		return float64(10 + i - 99)
	case i < 280:
		return float64(100 + 10*(i-189))
	case i < 370:
		return float64(1000 + 100*(i-279))
	}
	return math.Inf(1)
}

// Add counts one duration.
func (h *Hist) Add(d time.Duration) {
	if h == nil {
		return
	}
	h.b[histBucket(d)].Add(1)
	for {
		m := h.max.Load()
		if int64(d) <= m || h.max.CompareAndSwap(m, int64(d)) {
			return
		}
	}
}

// Lat sums a Hist up, ms (each percentile is its bucket's upper edge,
// at most Max).
type Lat struct {
	N    int     `json:"n"`
	P50  float64 `json:"p50"`
	P95  float64 `json:"p95"`
	P99  float64 `json:"p99"`
	Max  float64 `json:"max"`
	Over int     `json:"over100,omitempty"` // how many took over 100 ms
}

// Take returns what was counted since the last Take and starts afresh
// (nil if nothing was).
func (h *Hist) Take() *Lat {
	if h == nil {
		return nil
	}
	var c [histBuckets]uint32
	n := 0
	for i := range h.b {
		c[i] = h.b[i].Swap(0)
		n += int(c[i])
	}
	mx := float64(h.max.Swap(0)) / 1e6
	if n == 0 {
		return nil
	}
	l := &Lat{N: n, Max: round1(mx)}
	at := func(q float64) float64 {
		k := int(math.Ceil(q * float64(n)))
		s := 0
		for i, v := range c {
			s += int(v)
			if s >= k {
				return round1(math.Min(histUpper(i), mx))
			}
		}
		return l.Max
	}
	l.P50, l.P95, l.P99 = at(0.50), at(0.95), at(0.99)
	for i := histBucket(100 * time.Millisecond); i < histBuckets; i++ {
		l.Over += int(c[i])
	}
	return l
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
