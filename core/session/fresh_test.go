package session

import (
	"testing"
	"time"
)

// A path whose ping went unanswered for probeWait stops carrying traffic,
// and carries it again once anything arrives.
func TestFreshAfterUnansweredPing(t *testing.T) {
	now := time.Now()
	s := &Session{direct: true}
	s.LastRx.Store(now.Add(-3 * time.Second).UnixNano())
	s.probeAt.Store(now.Add(-time.Second).UnixNano())
	if !s.Fresh(now) {
		t.Fatal("left out before probeWait passed")
	}
	s.probeAt.Store(now.Add(-probeWait - time.Millisecond).UnixNano())
	if s.Fresh(now) {
		t.Fatal("still fresh after an unanswered ping")
	}
	s.LastRx.Store(now.UnixNano())
	if !s.Fresh(now) {
		t.Fatal("not fresh after an answer")
	}
	if got := s.Silent(now.Add(7 * time.Second)); got != 7*time.Second {
		t.Fatalf("Silent = %v", got)
	}
}
