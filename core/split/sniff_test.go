package split

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// clientHello returns the first bytes Go's TLS client sends to name (one
// or more TLS records).
func clientHello(t *testing.T, name string) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go tls.Client(a, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
	var out []byte
	buf := make([]byte, 4096)
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, err := b.Read(buf)
		out = append(out, buf[:n]...)
		if msg, ok := tlsHandshake(out); ok && len(msg) > 0 || err != nil {
			return out
		}
	}
}

func TestHelloHost(t *testing.T) {
	ch := clientHello(t, "Game.SU")
	if h, done := helloHost(ch); !done || h != "game.su" {
		t.Fatalf("TLS: %q %v", h, done)
	}
	// In pieces: not done until the whole message is there.
	if _, done := helloHost(ch[:40]); done {
		t.Fatal("done on a partial ClientHello")
	}
	// Split over two records.
	msg, _ := tlsHandshake(ch)
	two := []byte{0x16, 3, 1, 0, 50}
	two = append(two, msg[:50]...)
	two = append(two, 0x16, 3, 1, byte((len(msg)-50)>>8), byte(len(msg)-50))
	two = append(two, msg[50:]...)
	if h, done := helloHost(two); !done || h != "game.su" {
		t.Fatalf("two records: %q %v", h, done)
	}
	if h, done := helloHost([]byte("GET / HTTP/1.1\r\nHost: Example.com:8080\r\nAccept: */*\r\n\r\n")); !done || h != "example.com" {
		t.Fatalf("HTTP: %q %v", h, done)
	}
	if _, done := helloHost([]byte("GET / HTTP/1.1\r\nHo")); done {
		t.Fatal("done on a partial HTTP request")
	}
	if h, done := helloHost([]byte("SSH-2.0-OpenSSH\r\n")); !done || h != "" {
		t.Fatalf("other: %q %v", h, done)
	}
	// No name (an address): nothing.
	if h, _ := helloHost(clientHello(t, "")); h != "" {
		t.Fatalf("no SNI: %q", h)
	}
}

// RFC 9001, appendix A.
func TestQUICKeys(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	key, iv, hp := quicInitialKeys(quicV1, dcid)
	for _, c := range []struct{ got, want string }{
		{hex.EncodeToString(key), "1f369613dd76d5467730efcbe3b1a22d"},
		{hex.EncodeToString(iv), "fa044b2f42a3fd3b46fb255c"},
		{hex.EncodeToString(hp), "9f50449e04a0e810283a1e9933adedd2"},
	} {
		if c.got != c.want {
			t.Errorf("got %s, want %s", c.got, c.want)
		}
	}
	block, _ := aes.NewCipher(hp)
	sample, _ := hex.DecodeString("d1b1c98dd7689fb8ec11d242b123dc9b")
	var mask [16]byte
	block.Encrypt(mask[:], sample)
	if got := hex.EncodeToString(mask[:5]); got != "437b9aec36" {
		t.Errorf("mask %s", got)
	}
}

// quicSeal builds a client Initial packet carrying frames (the reverse of
// quicOpen).
func quicSeal(version uint32, dcid []byte, pn uint32, frames []byte) []byte {
	key, iv, hp := quicInitialKeys(version, dcid)
	first := byte(0xc3) // long header, fixed bit, Initial (v1), 4-byte packet number
	if version == quicV2 {
		first = 0xd3 // Initial is type 1 in version 2
	}
	h := []byte{first}
	h = binary.BigEndian.AppendUint32(h, version)
	h = append(h, byte(len(dcid)))
	h = append(h, dcid...)
	h = append(h, 0, 0) // no source ID, no token
	l := 4 + len(frames) + 16
	h = append(h, 0x40|byte(l>>8), byte(l))
	pnOff := len(h)
	h = binary.BigEndian.AppendUint32(h, pn)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 4; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	p := aead.Seal(append([]byte(nil), h...), nonce, frames, h)
	hb, _ := aes.NewCipher(hp)
	var mask [16]byte
	hb.Encrypt(mask[:], p[pnOff+4:pnOff+20])
	p[0] ^= mask[0] & 0x0f
	for i := 0; i < 4; i++ {
		p[pnOff+i] ^= mask[1+i]
	}
	return p
}

func cryptoFrame(off int, data []byte) []byte {
	f := []byte{0x06}
	f = binary.BigEndian.AppendUint32(f, 0x80000000|uint32(off)) // 4-byte varint
	f = binary.BigEndian.AppendUint16(f, 0x4000|uint16(len(data)))
	return append(f, data...)
}

// quicHello returns the Initial datagrams of a connection to name: the
// ClientHello in pieces, out of order, over two packets (as browsers send
// big ones), padded with PING and PADDING.
func quicHello(t *testing.T, version uint32, name string) [][]byte {
	msg, _ := tlsHandshake(clientHello(t, name))
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	half := len(msg) / 2
	var f1, f2 []byte
	f1 = append(f1, 0x01)
	f1 = append(f1, cryptoFrame(half, msg[half:])...)
	f1 = append(f1, make([]byte, 20)...)
	f2 = append(f2, cryptoFrame(0, msg[:half])...)
	f2 = append(f2, 0x02, 0x00, 0x00, 0x00, 0x00) // an ACK, for the parser's sake
	return [][]byte{quicSeal(version, dcid, 0, f1), quicSeal(version, dcid, 1, f2)}
}

func TestQUICSniff(t *testing.T) {
	for _, v := range []uint32{quicV1, quicV2} {
		var q quicSniff
		pk := quicHello(t, v, "voice.game.su")
		if h, ok := q.feed(pk[0]); ok {
			t.Fatalf("v%x: done after half: %q", v, h)
		}
		if h, ok := q.feed(pk[1]); !ok || h != "voice.game.su" {
			t.Fatalf("v%x: %q %v", v, h, ok)
		}
	}
	var q quicSniff
	if _, ok := q.feed([]byte("not quic at all")); !ok {
		t.Fatal("waited on a datagram that is not QUIC")
	}
}

// --- through the router ---

func sniffRules(def Route) Rules {
	return Rules{On: true, Default: def, Domains: []DomainRule{{Domain: "su", Route: Direct}, {Domain: "example.org", Route: VPN}}}
}

// A program with its own DNS connects to an address; the router reads the
// name and sends it direct.
func TestSniffTCPDirect(t *testing.T) {
	g := newRig(t, sniffRules(VPN), withSites)
	addr := echoTCP(t)
	extraSniffPort = addr.Port()
	defer func() { extraSniffPort = 0 }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, g.pc, far(addr), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	hello := clientHello(t, "play.game.su")
	c.Write(hello)
	got := make([]byte, len(hello))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, hello) {
		t.Fatalf("echo: %v", err)
	}
	cs := g.r.Conns(5)
	if len(cs) != 1 || cs[0].Route != Direct || cs[0].Host != "play.game.su" || !strings.Contains(cs[0].Why, "имя из соединения") {
		t.Fatalf("conns %+v", cs)
	}
	for len(g.vpn) > 0 {
		var p pkt
		if b := <-g.vpn; parse(b, &p) && p.key.proto == protoTCP {
			t.Fatalf("TCP reached the VPN: %+v", p.key)
		}
	}
}

// farServer is a server on the VPN's side: what the router sends to
// WireGuard reaches it, its answers come back through Write.
func farServer(t *testing.T, g *rig, port uint16) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(1024, 1280, "")
	s.CreateNIC(1, ep)
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4(testFar.As4()).WithPrefix()}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	l, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(testFar.As4()), Port: port}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); l.Close(); s.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	go func() {
		for {
			select {
			case b := <-g.vpn:
				pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
				ep.InjectInbound(ipv4.ProtocolNumber, pb)
				pb.DecRef()
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		for {
			pb := ep.ReadContext(ctx)
			if pb == nil {
				return
			}
			v := pb.ToView()
			pb.DecRef()
			g.r.Write([][]byte{append([]byte(nil), v.AsSlice()...)}, 0)
			v.Release()
		}
	}()
}

// The others go direct; a site sent through the VPN by name is relayed
// there by the router once it has read the name.
func TestSniffTCPRelay(t *testing.T) {
	g := newRig(t, sniffRules(Direct), withSites)
	const port = 4443
	extraSniffPort = port
	defer func() { extraSniffPort = 0 }()
	farServer(t, g, port)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, g.pc, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(testFar.As4()), Port: port}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	hello := clientHello(t, "video.example.org")
	msg := append(append([]byte(nil), hello...), bytes.Repeat([]byte("relayed "), 30000)...) // 240 KB more
	go c.Write(msg)
	got := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if n, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo: %d of %d, %v", n, len(msg), err)
	}
	cs := g.r.Conns(5)
	if len(cs) != 1 || cs[0].Route != VPN || cs[0].Host != "video.example.org" {
		t.Fatalf("conns %+v", cs)
	}
}

// A connection that says nothing for a while (a server speaks first) goes
// where it would have gone.
func TestSniffSilent(t *testing.T) {
	g := newRig(t, sniffRules(VPN), withSites)
	const port = 4444
	extraSniffPort = port
	defer func() { extraSniffPort = 0 }()
	farServer(t, g, port)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, g.pc, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(testFar.As4()), Port: port}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	time.Sleep(sniffWait + 300*time.Millisecond)
	c.Write([]byte("late"))
	got := make([]byte, 4)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "late" {
		t.Fatalf("echo: %q %v", got, err)
	}
	if cs := g.r.Conns(5); len(cs) != 1 || cs[0].Route != VPN || cs[0].Host != "" {
		t.Fatalf("conns %+v", cs)
	}
}

// QUIC: held until the name is read, then sent where it says.
func TestSniffQUIC(t *testing.T) {
	g := newRig(t, sniffRules(VPN), withSites)
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	port := srv.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	extraSniffPort = port
	defer func() { extraSniffPort = 0 }()
	fa := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(testFar.As4()), Port: port}
	c, err := gonet.DialUDP(g.pc, nil, &fa, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	pk := quicHello(t, quicV1, "cdn.game.su")
	for _, p := range pk {
		c.Write(p)
	}
	buf := make([]byte, 2000)
	srv.SetReadDeadline(time.Now().Add(3 * time.Second))
	for i := range pk {
		n, _, err := srv.ReadFromUDPAddrPort(buf)
		if err != nil || !bytes.Equal(buf[:n], pk[i]) {
			t.Fatalf("packet %d: %v", i, err)
		}
	}
	cs := g.r.Conns(5)
	if len(cs) != 1 || cs[0].Route != Direct || cs[0].Host != "cdn.game.su" {
		t.Fatalf("conns %+v", cs)
	}

	// Another site: through the VPN, all held packets in order.
	c2, err := gonet.DialUDP(g.pc, nil, &fa, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	for len(g.vpn) > 0 {
		<-g.vpn
	}
	pk2 := quicHello(t, quicV1, "www.other.com")
	for _, p := range pk2 {
		c2.Write(p)
	}
	for i := range pk2 {
		select {
		case b := <-g.vpn:
			var p pkt
			if !parse(b, &p) || !bytes.Equal(p.payload, pk2[i]) {
				t.Fatalf("VPN packet %d", i)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("packet %d did not reach the VPN", i)
		}
	}
	_ = netip.Addr{}
}
