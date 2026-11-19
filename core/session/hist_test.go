package session

import (
	"testing"
	"time"
)

func TestHist(t *testing.T) {
	var h Hist
	if h.Take() != nil {
		t.Fatal("empty histogram summed up")
	}
	for i := 0; i < 97; i++ {
		h.Add(15 * time.Millisecond)
	}
	h.Add(3500 * time.Microsecond)
	h.Add(180 * time.Millisecond)
	h.Add(2 * time.Second)
	l := h.Take()
	if l.N != 100 || l.P50 != 16 || l.P95 != 16 || l.P99 != 190 || l.Max != 2000 || l.Over != 2 {
		t.Fatalf("got %+v", *l)
	}
	h.Add(250 * time.Microsecond)
	if l := h.Take(); l.N != 1 || l.P50 != 0.3 || l.Max != 0.3 {
		t.Fatalf("not started afresh, or sub-ms wrong: %+v", *l)
	}
}
