package split

// The router's own way into the VPN. A connection whose route waits for
// the site's name is answered inside TurnVK (the computer's side ends in
// tcpDirect's stack); when the name says "through the VPN", the router
// opens the connection again from a TCP stack of its own (vpnRelay), from
// the computer's own address and port, and its packets go to WireGuard as
// if the computer had sent them. The far end's answers are taken out of
// Write and given to that stack.
//
// WireGuard only reads the adapter, so the router's packets are returned
// from Read. Once that may be needed, a goroutine (pump) reads the adapter
// and Read waits on both it and the router's packets.

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

type pumpBatch struct {
	bufs  [][]byte
	sizes []int
	n     int
	err   error
	done  chan struct{}
}

// pump reads the adapter for Read, batch by batch.
func (r *Router) pump(batch, size, offset int) {
	b := &pumpBatch{bufs: make([][]byte, batch), sizes: make([]int, batch), done: make(chan struct{})}
	for i := range b.bufs {
		b.bufs[i] = make([]byte, size)
	}
	for {
		b.n, b.err = r.inner.Read(b.bufs, b.sizes, offset)
		select {
		case r.pumpCh <- b:
		case <-r.ctx.Done():
			return
		}
		select {
		case <-b.done:
		case <-r.ctx.Done():
			return
		}
		if b.err != nil && (errors.Is(b.err, os.ErrClosed) || r.ctx.Err() != nil) {
			return
		}
	}
}

// readPumped returns the next packets: the router's own (own: true, for
// WireGuard as they are) or the adapter's.
func (r *Router) readPumped(bufs [][]byte, sizes []int, offset int) (n int, own bool, err error) {
	fill := func(first []byte) int {
		k := 0
		for b := first; ; {
			if offset+len(b) <= len(bufs[k]) {
				sizes[k] = copy(bufs[k][offset:], b)
				k++
			}
			if k == len(bufs) {
				return k
			}
			select {
			case b = <-r.injectQ:
				continue
			default:
			}
			return k
		}
	}
	select {
	case b := <-r.injectQ: // the router's own first: they are few
		return fill(b), true, nil
	default:
	}
	select {
	case b := <-r.injectQ:
		return fill(b), true, nil
	case pb := <-r.pumpCh:
		k := 0
		for i := 0; i < pb.n && k < len(bufs); i++ {
			if offset+pb.sizes[i] <= len(bufs[k]) {
				sizes[k] = copy(bufs[k][offset:], pb.bufs[i][offset:offset+pb.sizes[i]])
				k++
			}
		}
		err := pb.err
		pb.done <- struct{}{}
		return k, false, err
	case <-r.ctx.Done():
		return 0, false, os.ErrClosed
	}
}

// injectPkt queues a packet for WireGuard (dropped when the queue is full:
// TCP and QUIC send again).
func (r *Router) injectPkt(b []byte) {
	select {
	case r.injectQ <- b:
	default:
	}
}

// --- the relay's TCP stack ---

type vpnRelay struct {
	r     *Router
	s     *stack.Stack
	ep    *channel.Endpoint
	mu    sync.Mutex
	addrs map[netip.Addr]bool
	conns sync.Map
}

// vpnRelay returns the relay's stack, started on first use (nil: none yet
// and not to be started).
func (r *Router) vpnRelay() *vpnRelay {
	r.relayMu.Lock()
	defer r.relayMu.Unlock()
	return r.relay
}

func (r *Router) startRelay() (*vpnRelay, error) {
	r.relayMu.Lock()
	defer r.relayMu.Unlock()
	if r.relay != nil {
		return r.relay, nil
	}
	if r.ctx.Err() != nil {
		return nil, os.ErrClosed
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	v := &vpnRelay{r: r, s: s, ep: channel.New(1024, uint32(r.mtu), ""), addrs: map[netip.Addr]bool{}}
	if e := s.CreateNIC(1, v.ep); e != nil {
		s.Close()
		return nil, errors.New("relay NIC: " + e.String())
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	sack := tcpip.TCPSACKEnabled(true)
	mod := tcpip.TCPModerateReceiveBufferOption(true)
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20}
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20}
	for _, o := range []tcpip.SettableTransportProtocolOption{&sack, &mod, &snd, &rcv} {
		_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, o)
	}
	go v.out()
	r.relay = v
	return v, nil
}

// out sends the relay's packets to WireGuard.
func (v *vpnRelay) out() {
	for {
		pb := v.ep.ReadContext(v.r.ctx)
		if pb == nil {
			return
		}
		view := pb.ToView()
		pb.DecRef()
		b := make([]byte, view.Size())
		copy(b, view.AsSlice())
		view.Release()
		v.r.injectPkt(b)
	}
}

func (v *vpnRelay) inject(b []byte) {
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), b...))})
	v.ep.InjectInbound(ipv4.ProtocolNumber, pb)
	pb.DecRef()
}

// dial opens src -> dst through the VPN, from the computer's own address
// and port (that connection never left the computer, so the pair is free).
func (v *vpnRelay) dial(ctx context.Context, src, dst netip.AddrPort) (net.Conn, error) {
	v.mu.Lock()
	if !v.addrs[src.Addr()] {
		pa := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4(src.Addr().As4()).WithPrefix()}
		if e := v.s.AddProtocolAddress(1, pa, stack.AddressProperties{}); e != nil {
			v.mu.Unlock()
			return nil, errors.New("relay address: " + e.String())
		}
		v.addrs[src.Addr()] = true
	}
	v.mu.Unlock()
	return gonet.DialTCPWithBind(ctx, v.s,
		tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(src.Addr().As4()), Port: src.Port()},
		tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(dst.Addr().As4()), Port: dst.Port()},
		ipv4.ProtocolNumber)
}

func (v *vpnRelay) close() {
	v.conns.Range(func(k, _ any) bool {
		k.(net.Conn).Close()
		return true
	})
	v.ep.Close()
	v.s.Close()
}

// UsePump makes the router ready to send packets of its own (DialVPN)
// from the next adapter read on.
func (r *Router) UsePump() { r.wantPump.Store(true) }

// DialVPN opens a TCP connection of TurnVK's own through the VPN, from the
// tunnel's address (Options.Addr): for an app whose own sockets go around
// the tunnel (Android), to reach what the physical network blocks.
func (r *Router) DialVPN(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return r.dialVPN(ctx, dst, &flow{route: VPN, why: "TurnVK через VPN", path: "TurnVK", start: time.Now()})
}

// dialVPN opens a connection of the router's own through the VPN, from a
// free port of the tunnel's address (Options.Addr); f describes it.
func (r *Router) dialVPN(ctx context.Context, dst netip.AddrPort, f *flow) (net.Conn, error) {
	if !r.o.Addr.Is4() || !dst.Addr().Is4() {
		return nil, errors.New("no tunnel address")
	}
	rl, err := r.startRelay()
	if err != nil {
		return nil, err
	}
	r.wantPump.Store(true)
	// A free port: no connection of the computer's uses it to dst.
	var key flowKey
	r.mu.Lock()
	for i := 0; ; i++ {
		key = flowKey{protoTCP, netip.AddrPortFrom(r.o.Addr, uint16(61000+rand.IntN(4000))), dst}
		if r.flows[key] == nil || i > 50 {
			break
		}
	}
	f.key = key
	f.touch(time.Now().UnixNano())
	f.relayed.Store(true)
	r.flows[key] = f
	r.mu.Unlock()
	r.relayN.Add(1)
	c, err := rl.dial(ctx, key.src, dst)
	if err != nil {
		f.relayed.Store(false)
		f.closed.Store(true)
		r.relayN.Add(-1)
		return nil, err
	}
	return &relayConn{Conn: c, done: func() {
		f.closed.Store(true)
		if f.relayed.CompareAndSwap(true, false) {
			r.relayN.Add(-1)
		}
	}}, nil
}

// VPNResolver resolves names through the tunnel's DNS servers, over TCP
// connections of DialVPN.
func (r *Router) VPNResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var last error = errors.New("no DNS servers in the tunnel")
			for _, d := range r.o.DNS {
				c, err := r.DialVPN(ctx, netip.AddrPortFrom(d, 53))
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		},
	}
}

// VPNDialContext dials "host:port" through the VPN (for http.Transport).
func (r *Router) VPNDialContext(ctx context.Context, _, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	addrs, err := r.VPNResolver().LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	var last error
	for i, a := range addrs {
		if i == 3 {
			break
		}
		c, err := r.DialVPN(ctx, netip.AddrPortFrom(a.Unmap(), uint16(p)))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}
