package split

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// control binds the sockets of direct connections to the physical network.
func (r *Router) control(_, _ string, c syscall.RawConn) error {
	if r.o.Protect == nil {
		return nil
	}
	var perr error
	if err := c.Control(func(fd uintptr) { perr = r.o.Protect(fd) }); err != nil {
		return err
	}
	return perr
}

func (r *Router) remap(a netip.AddrPort) netip.AddrPort {
	if r.o.remap != nil {
		return r.o.remap(a)
	}
	return a
}

// unmap is remap's reverse (tests only: remap there is its own reverse).
func (r *Router) unmap(a netip.AddrPort) netip.AddrPort { return r.remap(a) }

// --- TCP ---

// tcpDirect answers direct TCP connections in a TCP stack of its own
// (gVisor, as the console client's proxy): for each, it first connects to
// the destination on the physical network, then accepts the program's
// connection and copies data both ways. A destination that refuses or
// does not answer gets the program a reset, as it would directly.
type tcpDirect struct {
	r     *Router
	s     *stack.Stack
	ep    *channel.Endpoint
	conns sync.Map // net.Conn -> struct{}: closed with the router
}

func newTCPDirect(r *Router) (*tcpDirect, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	t := &tcpDirect{r: r, s: s, ep: channel.New(1024, uint32(r.mtu), "")}
	fail := func(what string, e tcpip.Error) error {
		s.Close()
		return errors.New(what + ": " + e.String())
	}
	if e := s.CreateNIC(1, t.ep); e != nil {
		return nil, fail("NIC", e)
	}
	// Take connections to any address, and answer from it.
	if e := s.SetPromiscuousMode(1, true); e != nil {
		return nil, fail("promiscuous mode", e)
	}
	if e := s.SetSpoofing(1, true); e != nil {
		return nil, fail("spoofing", e)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	// Reno, gVisor's default, not cubic as in the console client: here the
	// stack talks to programs on the same computer, and cubic stalls at
	// such round trips (a test sends 320 KB through it).
	sack := tcpip.TCPSACKEnabled(true)
	mod := tcpip.TCPModerateReceiveBufferOption(true)
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20}
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20}
	for _, o := range []tcpip.SettableTransportProtocolOption{&sack, &mod, &snd, &rcv} {
		if e := s.SetTransportProtocolOption(tcp.ProtocolNumber, o); e != nil {
			return nil, fail("TCP options", e)
		}
	}
	_ = s.SetOption(tcpip.SendBufferSizeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20})
	_ = s.SetOption(tcpip.ReceiveBufferSizeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20})
	fwd := tcp.NewForwarder(s, 0, 4096, t.accept)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	go t.out()
	return t, nil
}

func (t *tcpDirect) inject(b []byte) {
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
	t.ep.InjectInbound(ipv4.ProtocolNumber, pb)
	pb.DecRef()
}

// out sends the stack's packets (its side of the connections) to the
// computer.
func (t *tcpDirect) out() {
	for {
		pb := t.ep.ReadContext(t.r.ctx)
		if pb == nil {
			return
		}
		v := pb.ToView()
		pb.DecRef()
		b := make([]byte, v.Size())
		copy(b, v.AsSlice())
		v.Release()
		t.r.writeOut([][]byte{b}, 0)
	}
}

func (t *tcpDirect) close() {
	t.conns.Range(func(k, _ any) bool {
		k.(net.Conn).Close()
		return true
	})
	t.ep.Close()
	t.s.Close()
}

func (t *tcpDirect) accept(req *tcp.ForwarderRequest) {
	id := req.ID()
	src := netip.AddrPortFrom(netip.AddrFrom4(id.RemoteAddress.As4()), id.RemotePort)
	dst := netip.AddrPortFrom(netip.AddrFrom4(id.LocalAddress.As4()), id.LocalPort)
	f := t.r.flowFor(flowKey{protoTCP, src, dst})
	if f != nil && f.sniffing {
		t.acceptSniffing(req, f, src, dst)
		return
	}
	go func() {
		d := net.Dialer{Timeout: 10 * time.Second, Control: t.r.control, KeepAlive: 30 * time.Second}
		out, err := t.r.dialTCP(&d, dst)
		if err != nil {
			req.Complete(true)
			if f != nil {
				f.closed.Store(true)
			}
			return
		}
		var wq waiter.Queue
		ep, e := req.CreateEndpoint(&wq)
		if e != nil {
			req.Complete(true)
			out.Close()
			if f != nil {
				f.closed.Store(true)
			}
			return
		}
		req.Complete(false)
		in := gonet.NewTCPConn(&wq, ep)
		t.conns.Store(net.Conn(in), struct{}{})
		t.conns.Store(out, struct{}{})
		splice(in, out, f)
		t.conns.Delete(net.Conn(in))
		t.conns.Delete(out)
		if f != nil {
			f.closed.Store(true)
			f.touch(time.Now().UnixNano())
		}
	}()
}

// dialTCP connects to the destination; a placeholder is dialled by the
// site's name, address after address.
func (r *Router) dialTCP(d *net.Dialer, dst netip.AddrPort) (net.Conn, error) {
	if !isFake(dst.Addr()) {
		return d.DialContext(r.ctx, "tcp4", r.remap(dst).String())
	}
	name := r.o.Fake.Name(dst.Addr())
	if name == "" {
		return nil, errors.New("unknown placeholder " + dst.Addr().String())
	}
	addrs := r.resolve(name)
	if len(addrs) == 0 {
		return nil, errors.New("cannot resolve " + name)
	}
	var err error
	for i, a := range addrs {
		if i == 3 {
			break
		}
		var c net.Conn
		if c, err = d.DialContext(r.ctx, "tcp4", r.remap(netip.AddrPortFrom(a, dst.Port())).String()); err == nil {
			return c, nil
		}
	}
	return nil, err
}

type halfCloser interface{ CloseWrite() error }

// splice copies both ways until both directions end. Bytes from the
// destination count as the flow's download (uploads are counted as packets
// enter the router).
func splice(in, out net.Conn, f *flow) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn, count *atomic.Uint64) {
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if count != nil {
					count.Add(uint64(n))
					f.touch(time.Now().UnixNano())
				}
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		if hc, ok := dst.(halfCloser); ok {
			hc.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	var down *atomic.Uint64
	if f != nil {
		down = &f.down
	}
	go cp(out, in, nil)
	go cp(in, out, down)
	<-done
	// One side finished: give the other a while to drain, then close.
	t := time.NewTimer(2 * time.Minute)
	select {
	case <-done:
	case <-t.C:
	}
	t.Stop()
	in.Close()
	out.Close()
}

// --- UDP ---

// udpNAT sends direct UDP from one socket per program socket, so a game
// talking to many servers (or to other players) from one port keeps one
// outside port for all of them, as without a VPN.
type udpNAT struct {
	r     *Router
	mu    sync.Mutex
	socks map[netip.AddrPort]*natSock // the program's address
	id    atomic.Uint32
}

type natSock struct {
	r      *Router
	c      *net.UDPConn
	client netip.AddrPort
	mu     sync.Mutex
	fakeOf map[netip.AddrPort]netip.AddrPort // real site -> its placeholder
	last   atomic.Int64
}

func newUDPNAT(r *Router) *udpNAT { return &udpNAT{r: r, socks: map[netip.AddrPort]*natSock{}} }

func (u *udpNAT) send(f *flow, payload []byte) {
	s := u.sock(f.key.src)
	if s == nil {
		return
	}
	s.last.Store(time.Now().UnixNano())
	dst := f.key.dst
	if isFake(dst.Addr()) {
		name := u.r.o.Fake.Name(dst.Addr())
		if name == "" {
			return
		}
		if addrs, ok := u.r.resolveCached(name); ok {
			s.toSite(payload, dst, addrs)
			return
		}
		// Not to hold up every other packet while resolving.
		p := append([]byte(nil), payload...)
		go func() { s.toSite(p, dst, u.r.resolve(name)) }()
		return
	}
	_, _ = s.c.WriteToUDPAddrPort(payload, u.r.remap(dst))
}

// toSite sends to a site behind a placeholder; its answers will come back
// from the placeholder.
func (s *natSock) toSite(payload []byte, fake netip.AddrPort, addrs []netip.Addr) {
	if len(addrs) == 0 {
		return
	}
	real := netip.AddrPortFrom(addrs[0], fake.Port())
	s.mu.Lock()
	if s.fakeOf == nil {
		s.fakeOf = map[netip.AddrPort]netip.AddrPort{}
	}
	s.fakeOf[real] = fake
	s.mu.Unlock()
	_, _ = s.c.WriteToUDPAddrPort(payload, s.r.remap(real))
}

func (u *udpNAT) sock(client netip.AddrPort) *natSock {
	u.mu.Lock()
	defer u.mu.Unlock()
	if s := u.socks[client]; s != nil {
		return s
	}
	if u.r.ctx.Err() != nil {
		return nil
	}
	lc := net.ListenConfig{Control: u.r.control}
	pc, err := lc.ListenPacket(u.r.ctx, "udp4", "0.0.0.0:0")
	if err != nil {
		u.r.o.Logf("split: UDP socket: %v", err)
		return nil
	}
	s := &natSock{r: u.r, c: pc.(*net.UDPConn), client: client}
	s.last.Store(time.Now().UnixNano())
	u.socks[client] = s
	go u.read(s)
	return s
}

func (u *udpNAT) read(s *natSock) {
	defer func() {
		u.mu.Lock()
		if u.socks[s.client] == s {
			delete(u.socks, s.client)
		}
		u.mu.Unlock()
		s.c.Close()
	}()
	buf := make([]byte, maxDatagram)
	for {
		_ = s.c.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, from, err := s.c.ReadFromUDPAddrPort(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && u.r.ctx.Err() == nil &&
				time.Since(time.Unix(0, s.last.Load())) < udpIdle {
				continue
			}
			return
		}
		from = u.r.unmap(netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
		s.mu.Lock()
		if fk, ok := s.fakeOf[from]; ok {
			from = fk
		}
		s.mu.Unlock()
		s.last.Store(time.Now().UnixNano())
		if f := u.r.flowFor(flowKey{protoUDP, s.client, from}); f != nil {
			f.down.Add(uint64(n + 28))
			f.touch(time.Now().UnixNano())
		}
		u.r.writeOut(udpPackets(from, s.client, buf[:n], u.r.mtu, 0, uint16(u.id.Add(1))), 0)
	}
}

func (u *udpNAT) close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, s := range u.socks {
		s.c.Close()
	}
}
