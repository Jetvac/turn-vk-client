package diag

import (
	"strings"
	"testing"
)

func TestPingSum(t *testing.T) {
	r := PingResult{Via: "test", Got: []float64{20, 22, 21, -1, 95, 20, 21, 23, 22, 20}}
	r.Sum()
	if r.Sent != 10 || r.Lost != 1 || r.Min != 20 || r.P50 != 21 || r.Max != 95 || r.Spikes != 1 {
		t.Fatalf("got %+v", r)
	}
	if r.Jitter < 10 || r.Jitter > 20 {
		t.Fatalf("jitter %v", r.Jitter)
	}
	if s := r.Text(); !strings.Contains(s, "медиана 21 мс") || !strings.Contains(s, "всплесков 1") {
		t.Fatal(s)
	}
	none := PingResult{Got: []float64{-1, -1}, Error: "timeout"}
	none.Sum()
	if !strings.Contains(none.Text(), "не удалось — timeout") {
		t.Fatal(none.Text())
	}
}
