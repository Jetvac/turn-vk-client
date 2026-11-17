//go:build !windows

package split

// NewOwner returns nil: programs are told apart only on Windows (Android
// routes apps with the system's own per-app VPN settings).
func NewOwner() Owner { return nil }

// FlushDNS does nothing outside Windows.
func FlushDNS() {}
