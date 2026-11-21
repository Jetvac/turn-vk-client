//go:build linux || android

package mobile

import "github.com/Jetvac/turn-vk-client/core/engine"

// Mark notes that the user says something is wrong right now (note: what,
// may be empty) for the server's statistics, with the state of the
// connection; it returns the line for the app's log.
func Mark(note string) string {
	mu.Lock()
	e := current
	mu.Unlock()
	return engine.Mark(e, note)
}
