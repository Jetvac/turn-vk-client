package split

// The site's name from the connection itself, when DNS did not tell: the
// server name a TLS ClientHello carries (HTTPS and most other TLS), the
// Host header of plain HTTP, and the same ClientHello inside QUIC's first
// packet (quic.go). Programs that resolve names their own way (encrypted
// DNS of their own, Android's private DNS, addresses built in) are routed
// by site rules too, connection by connection.
//
// A TCP connection waiting for its name is answered inside TurnVK (as a
// direct one), its first bytes are read (at most a second), and then it is
// opened direct or through the VPN (inject.go), the bytes sent on first.

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// sniffWait: how long a connection may take to send its first bytes.
const sniffWait = time.Second

// extraSniffPort: tests' servers listen on ports of their own.
var extraSniffPort uint16

func sniffPort(proto uint8, port uint16) bool {
	if port != 0 && port == extraSniffPort {
		return true
	}
	if proto == protoUDP {
		return port == 443
	}
	return port == 443 || port == 80 || port == 8443 || port == 8080
}

// sniffable: some rule for sites sends sites the other way than d, so the
// name matters.
func (m *matcher) sniffable(d Route) bool {
	if d == VPN {
		return m.directSites
	}
	return m.vpnSites
}

// decideSniffed routes a connection once its name is known ("" when the
// connection did not tell).
func (r *Router) decideSniffed(f *flow, host string, prelim Decision) Decision {
	if host == "" {
		return prelim
	}
	m := r.m.Load()
	if d, ok := m.fixed(f.key.dst.Addr()); ok {
		return d
	}
	d := m.decide(f.key.dst.Addr(), host, f.proc)
	if strings.HasPrefix(d.Why, "сайт ") || strings.HasPrefix(d.Why, "список ") {
		d.Why += " (имя из соединения)"
	}
	return d
}

// settle records the route found for a waiting connection.
func (r *Router) settle(f *flow, host string, d Decision) {
	r.mu.Lock()
	f.route, f.why = d.Route, d.Why
	if host != "" {
		f.host = host
	}
	f.sniffing = false
	r.mu.Unlock()
	if d.Route == Direct {
		name := "?"
		if f.path != "" {
			name = baseName(f.path)
		}
		r.mu.Lock()
		lk := name + "|" + d.Why
		first := !r.logged[lk] && len(r.logged) < 200
		if first {
			r.logged[lk] = true
		}
		r.mu.Unlock()
		if first {
			r.o.Logf("split: %s goes direct (%s)", name, d.Why)
		}
	}
}

// acceptSniffing takes a connection waiting for its name: it is accepted,
// its first bytes read, and it is opened where its name says.
func (t *tcpDirect) acceptSniffing(req *tcp.ForwarderRequest, f *flow, src, dst netip.AddrPort) {
	r := t.r
	prelim := r.m.Load().decide(dst.Addr(), "", f.proc)
	var wq waiter.Queue
	ep, e := req.CreateEndpoint(&wq)
	if e != nil {
		req.Complete(true)
		f.closed.Store(true)
		return
	}
	req.Complete(false)
	in := gonet.NewTCPConn(&wq, ep)
	go func() {
		defer f.touch(time.Now().UnixNano())
		_ = in.SetReadDeadline(time.Now().Add(sniffWait))
		head, host := readHello(in)
		_ = in.SetReadDeadline(time.Time{})
		d := r.decideSniffed(f, host, prelim)
		r.settle(f, host, d)
		var out net.Conn
		var err error
		if d.Route == Direct {
			dl := net.Dialer{Timeout: 10 * time.Second, Control: r.control, KeepAlive: 30 * time.Second}
			out, err = r.dialTCP(&dl, dst)
		} else {
			out, err = r.relayDial(f, src, dst)
		}
		if err != nil {
			ep.Abort() // the program gets a reset, as from a refusing server
			in.Close()
			f.closed.Store(true)
			return
		}
		if len(head) > 0 {
			if _, err := out.Write(head); err != nil {
				ep.Abort()
				in.Close()
				out.Close()
				f.closed.Store(true)
				return
			}
		}
		t.conns.Store(net.Conn(in), struct{}{})
		t.conns.Store(out, struct{}{})
		splice(in, out, f)
		t.conns.Delete(net.Conn(in))
		t.conns.Delete(out)
		f.closed.Store(true)
	}()
}

// relayDial opens the connection through the VPN (inject.go).
func (r *Router) relayDial(f *flow, src, dst netip.AddrPort) (net.Conn, error) {
	rl, err := r.startRelay()
	if err != nil {
		return nil, err
	}
	f.relayed.Store(true)
	r.relayN.Add(1)
	ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
	defer cancel()
	c, err := rl.dial(ctx, src, dst)
	if err != nil {
		f.relayed.Store(false)
		r.relayN.Add(-1)
		return nil, err
	}
	return &relayConn{Conn: c, done: func() {
		if f.relayed.CompareAndSwap(true, false) {
			r.relayN.Add(-1)
		}
	}}, nil
}

// relayConn counts open relayed connections (Write looks for their
// packets only while there are some).
type relayConn struct {
	net.Conn
	done func()
}

func (c *relayConn) Close() error {
	err := c.Conn.Close()
	c.done()
	return err
}

func (c *relayConn) CloseWrite() error {
	if hc, ok := c.Conn.(halfCloser); ok {
		return hc.CloseWrite()
	}
	return nil
}

// readHello reads a connection's first bytes, until they hold the site's
// name, cannot hold it, or the deadline passes; host is "" when not found.
func readHello(c net.Conn) (head []byte, host string) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for len(buf) < 16<<10 {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if len(buf) > 0 {
			h, done := helloHost(buf)
			if done {
				return buf, h
			}
		}
		if err != nil {
			break
		}
	}
	h, _ := helloHost(buf)
	return buf, h
}

// helloHost finds the name in a connection's first bytes; done is false
// while more bytes could still bring it.
func helloHost(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", false
	}
	if b[0] == 0x16 { // TLS handshake record
		msg, complete := tlsHandshake(b)
		if !complete {
			return "", false
		}
		return clientHelloSNI(msg), true
	}
	if isHTTPMethod(b) {
		end := bytes.Index(b, []byte("\r\n\r\n"))
		if end < 0 {
			return "", len(b) >= 8<<10
		}
		return httpHost(b[:end]), true
	}
	return "", true // something else: no name in it
}

// tlsHandshake joins the handshake records at the start of b into the
// first handshake message; complete once it is whole (or b is not TLS).
func tlsHandshake(b []byte) ([]byte, bool) {
	var msg []byte
	for len(b) >= 5 {
		if b[0] != 0x16 {
			return msg, true
		}
		l := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < 5+l {
			msg = append(msg, b[5:]...)
			return msg, enough(msg)
		}
		msg = append(msg, b[5:5+l]...)
		b = b[5+l:]
		if enough(msg) {
			return msg, true
		}
	}
	return msg, enough(msg)
}

func enough(msg []byte) bool {
	if len(msg) < 4 {
		return false
	}
	l := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	return len(msg) >= 4+l || msg[0] != 1
}

// clientHelloSNI reads the server name of a ClientHello handshake message
// (type, 3-byte length, body).
func clientHelloSNI(msg []byte) string {
	if len(msg) < 4 || msg[0] != 1 {
		return ""
	}
	l := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	b := msg[4:]
	if len(b) > l {
		b = b[:l]
	}
	// version, random
	if len(b) < 34 {
		return ""
	}
	b = b[34:]
	skip := func(lenBytes int) bool {
		if len(b) < lenBytes {
			return false
		}
		n := 0
		for i := 0; i < lenBytes; i++ {
			n = n<<8 | int(b[i])
		}
		if len(b) < lenBytes+n {
			return false
		}
		b = b[lenBytes+n:]
		return true
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, cipher suites, compression
		return ""
	}
	if len(b) < 2 {
		return ""
	}
	ext := b[2:]
	if n := int(binary.BigEndian.Uint16(b)); n < len(ext) {
		ext = ext[:n]
	}
	for len(ext) >= 4 {
		typ, n := binary.BigEndian.Uint16(ext), int(binary.BigEndian.Uint16(ext[2:]))
		if len(ext) < 4+n {
			return ""
		}
		data := ext[4 : 4+n]
		ext = ext[4+n:]
		if typ != 0 { // server_name
			continue
		}
		if len(data) < 2 {
			return ""
		}
		list := data[2:]
		for len(list) >= 3 {
			nt, nl := list[0], int(binary.BigEndian.Uint16(list[1:]))
			if len(list) < 3+nl {
				return ""
			}
			if nt == 0 {
				return cleanHost(string(list[3 : 3+nl]))
			}
			list = list[3+nl:]
		}
		return ""
	}
	return ""
}

func isHTTPMethod(b []byte) bool {
	for _, m := range []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "} {
		n := min(len(b), len(m))
		if string(b[:n]) == m[:n] {
			return true
		}
	}
	return false
}

func httpHost(head []byte) string {
	for _, line := range strings.Split(string(head), "\r\n")[1:] {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), "host") {
			v = strings.TrimSpace(v)
			if h, _, err := net.SplitHostPort(v); err == nil {
				v = h
			}
			return cleanHost(v)
		}
	}
	return ""
}

// cleanHost keeps a name that looks like one (lower case, no final dot).
func cleanHost(h string) string {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " /\\\x00") {
		return ""
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "" // an address, not a name
	}
	return h
}
