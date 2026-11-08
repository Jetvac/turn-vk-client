// Package netx opens the client's outer sockets (TURN, VK API, DNS) so that
// they never loop back into the VPN tunnel the client itself provides.
//
// Every platform supplies a Protect hook: on Android it calls
// VpnService.protect(fd); on Windows it binds the socket to the physical
// interface (IP_UNICAST_IF). Without a hook (proxy mode) sockets are plain.
package netx

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"
)

// Protector marks a socket so that its traffic bypasses the tunnel.
type Protector func(fd uintptr) error

// Net creates protected sockets and resolves names through protected DNS.
type Net struct {
	Protect Protector
	// DNS servers ("ip:port") used to resolve the server, VK API and TURN
	// hosts. Empty means the system resolver.
	DNS []string
}

// DefaultDNS are public resolvers reachable from Russian networks.
var DefaultDNS = []string{"77.88.8.8:53", "77.88.8.1:53"}

func (n *Net) control(_, _ string, c syscall.RawConn) error {
	if n == nil || n.Protect == nil {
		return nil
	}
	var perr error
	if err := c.Control(func(fd uintptr) { perr = n.Protect(fd) }); err != nil {
		return err
	}
	return perr
}

// ListenUDP opens an unconnected IPv4 UDP socket on a random port.
func (n *Net) ListenUDP(ctx context.Context) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: n.control}
	pc, err := lc.ListenPacket(ctx, "udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// Dialer returns a dialer for protected TCP connections (VK API).
func (n *Net) Dialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: n.control, Resolver: n.Resolver()}
}

// Resolver resolves through the configured DNS servers over protected
// sockets, trying each in turn, then the system resolver's choice.
func (n *Net) Resolver() *net.Resolver {
	if n == nil || len(n.DNS) == 0 {
		if n != nil && n.Protect != nil {
			d := &net.Dialer{Timeout: 3 * time.Second, Control: n.control}
			return &net.Resolver{PreferGo: true, Dial: d.DialContext}
		}
		return net.DefaultResolver
	}
	servers := n.DNS
	d := &net.Dialer{Timeout: 3 * time.Second, Control: n.control}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var last error
			for _, s := range servers {
				c, err := d.DialContext(ctx, network, s)
				if err == nil {
					return c, nil
				}
				last = err
			}
			if last == nil {
				last = errors.New("no DNS servers")
			}
			return nil, last
		},
	}
}

// ResolveUDP resolves "host:port" to an IPv4 UDP address.
func (n *Net) ResolveUDP(ctx context.Context, hostport string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		return net.ResolveUDPAddr("udp", hostport)
	}
	ips, err := n.Resolver().LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("no IPv4 address for " + host)
	}
	return net.ResolveUDPAddr("udp", net.JoinHostPort(ips[0].String(), port))
}
