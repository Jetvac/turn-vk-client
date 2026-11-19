package session

import (
	"testing"
	"time"
)

// A steady stream of small packets makes traffic interactive, for a while
// after it stops; a few now and then do not.
func TestInteractive(t *testing.T) {
	var it Interactive
	t0 := time.Now().UnixNano()
	sec := int64(time.Second)
	it.Note(t0, 0)
	if it.Note(t0+sec, 5) {
		t.Fatal("5 small packets a second judged interactive")
	}
	for i := int64(0); i < 10; i++ {
		it.Note(t0+sec+i*sec/10, 3) // 30 a second
	}
	if !it.Note(t0+2*sec, 0) {
		t.Fatal("30 small packets a second not interactive")
	}
	if !it.Note(t0+5*sec, 0) {
		t.Fatal("not held after the stream stopped")
	}
	if it.Note(t0+8*sec, 0) {
		t.Fatal("still interactive long after")
	}
	if it.Secs.Load() == 0 {
		t.Fatal("seconds not counted")
	}
}

// Tight: a smaller burst, and the rate goes down at a shorter queue.
func TestTightPath(t *testing.T) {
	var r PathRate
	now := time.Now().UnixNano()
	r.Refill(now)
	r.Refill(now + int64(time.Second))
	if r.Tokens != pathBurst || r.Queued() != 0 {
		t.Fatalf("normal: tokens %v, queued %v", r.Tokens, r.Queued())
	}
	r.Tight.Store(true)
	r.Refill(now + 2*int64(time.Second))
	if r.Tokens != tightBurst || r.Queued() != 0 {
		t.Fatalf("tight: tokens %v, queued %v", r.Tokens, r.Queued())
	}
	if r.queueLimit() != tightQueueDelay {
		t.Fatal("queue limit not lowered")
	}
}
