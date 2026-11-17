// Package redact takes secrets out of text that leaves the device
// (diagnostic reports, statistics).
package redact

import "regexp"

var (
	reLink  = regexp.MustCompile(`wdtt://\S+`)
	reVK    = regexp.MustCompile(`(?i)(vk\.com/call/join/|join/)[A-Za-z0-9_\-]+`)
	reToken = regexp.MustCompile(`(?i)(access_token|token|password|pass|key|sig|hash)=([^&\s"]+)`)
	reLong  = regexp.MustCompile(`[A-Za-z0-9+/_\-]{32,}={0,2}`)
)

// String takes secrets out of a line: links, VK call ids, tokens and any
// long key-like string.
func String(s string) string {
	s = reLink.ReplaceAllString(s, "wdtt://<hidden>")
	s = reVK.ReplaceAllString(s, "${1}<hidden>")
	s = reToken.ReplaceAllString(s, "$1=<hidden>")
	s = reLong.ReplaceAllString(s, "<hidden>")
	return s
}
