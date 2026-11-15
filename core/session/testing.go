package session

import "time"

// NewTestSession returns an unconnected direct session through server, for
// tests of other packages that only read its counters.
func NewTestSession(server string) *Session {
	s := &Session{Server: server, Started: time.Now(), direct: true, done: make(chan struct{})}
	s.LastRx.Store(time.Now().UnixNano())
	return s
}
