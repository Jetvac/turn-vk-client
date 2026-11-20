package session

import (
	"testing"
	"time"
)

// A path that spikes now and then scores worse than a steady one with a
// slightly longer round trip, even right after a quick ping.
func TestJitter(t *testing.T) {
	ms := int64(time.Millisecond)
	var steady, spiky jitter
	var a, b int64
	for i := 0; i < 40; i++ {
		a = steady.add(35 * ms)
		r := 25 * ms
		if i%5 == 0 {
			r = 230 * ms
		}
		b = spiky.add(r)
	}
	b = spiky.add(25 * ms) // a lucky last ping
	if b <= a {
		t.Fatalf("spiky %v not worse than steady %v", time.Duration(b), time.Duration(a))
	}
	if a < 35*ms || a > 40*ms {
		t.Fatalf("steady path expects %v", time.Duration(a))
	}
}
