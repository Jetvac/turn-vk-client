package split

import "net/netip"

// Owner finds the program that opened a connection, by the local end of its
// socket (the packet's source) and, for TCP, the remote end.
type Owner interface {
	// Lookup returns nil when the socket is not found (it closed already,
	// or the system did not list it yet). parents asks for Proc.Parents.
	Lookup(proto uint8, local, remote netip.AddrPort, parents bool) *Proc
}
