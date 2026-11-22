package session

import "time"

// NewTestSession returns an unconnected direct session through server, for
// tests of other packages that only read its counters. Its probes go
// nowhere (no answer); SetProbe makes it answer.
func NewTestSession(server string) *Session {
	s := &Session{Server: server, Started: time.Now(), direct: true, done: make(chan struct{})}
	s.LastRx.Store(time.Now().UnixNano())
	s.testProbe = func(*Session) {}
	return s
}

// SetProbe sets what a probe of a test session does once it is noted as
// one, as a real probe is: answer, for one, with Answer.
func (s *Session) SetProbe(f func(*Session)) { s.testProbe = f }

// Answer is what the server's answer to a probe does to the session.
func (s *Session) Answer() { s.LastRx.Store(time.Now().UnixNano()) }
