package split

// Sites by name. Windows asks the tunnel's DNS servers, so every query
// passes the router. For a name that a rule sends direct, the router
// answers itself with a placeholder address from 198.18.0.0/15, one per
// name: a connection to that address is that site, exactly, even when the
// site shares its real addresses with others (CDNs). Direct connections to a
// placeholder are opened to the real site by name, resolved on the physical
// network (so a CDN picks servers close to the computer, not to the VPN
// server).
//
// Other names are resolved through the VPN as before; the router notes the
// answers (address -> name) to show names in the connection list and to
// apply rules that send sites through the VPN.

import (
	"context"
	"encoding/binary"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var fakeNet = netip.MustParsePrefix("198.18.0.0/15")

// The answers' TTL: programs ask again soon, so a changed rule takes
// effect quickly and a placeholder does not outlive TurnVK in their caches.
const fakeTTL = 1

// Firefox asks this name before turning on its own encrypted DNS; "no such
// name" keeps it on the system's DNS, which rules by name need.
const canary = "use-application-dns.net"

// Fake hands out placeholder addresses. It outlives connections (the app
// keeps one), so a program that cached a placeholder keeps reaching its site
// after a reconnect.
type Fake struct {
	mu     sync.Mutex
	byName map[string]netip.Addr
	byIP   map[netip.Addr]string
	next   uint32
}

// NewFake returns an empty pool.
func NewFake() *Fake {
	return &Fake{byName: map[string]netip.Addr{}, byIP: map[netip.Addr]string{}}
}

const fakeSize = 1 << 17 // a /15

func (f *Fake) addr(name string) netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a, ok := f.byName[name]; ok {
		return a
	}
	if f.next < 2 || f.next >= fakeSize-1 {
		f.next = 2
	}
	base := binary.BigEndian.Uint32(fakeNet.Addr().AsSlice())
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], base+f.next)
	f.next++
	a := netip.AddrFrom4(b)
	if old, ok := f.byIP[a]; ok { // the pool went round: reuse the oldest
		delete(f.byName, old)
	}
	f.byName[name], f.byIP[a] = a, name
	return a
}

// Name returns the site behind a placeholder ("" when unknown).
func (f *Fake) Name(a netip.Addr) string {
	if f == nil {
		return ""
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.byIP[a]
}

func isFake(a netip.Addr) bool { return fakeNet.Contains(a) }

// --- the names of real addresses ---

type hostEntry struct {
	name string
	exp  int64 // unix ns
}

const (
	hostMinTTL = 5 * time.Minute // long connections outlive short TTLs
	hostMaxTTL = 6 * time.Hour
	maxHosts   = 50000
)

func (r *Router) hostOf(a netip.Addr) string {
	r.hmu.Lock()
	defer r.hmu.Unlock()
	return r.hosts[a].name
}

// dnsQuery answers a query for a site sent direct; false leaves it to the
// VPN's DNS.
func (r *Router) dnsQuery(p *pkt, m *matcher) bool {
	var ps dnsmessage.Parser
	h, err := ps.Start(p.payload)
	if err != nil || h.Response || h.OpCode != 0 {
		return false
	}
	q, err := ps.Question()
	if err != nil {
		return false
	}
	if _, err := ps.Question(); err != dnsmessage.ErrSectionDone {
		return false
	}
	name := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")
	rcode := dnsmessage.RCodeSuccess
	var ip netip.Addr
	if name == canary {
		rcode = dnsmessage.RCodeNameError
	} else {
		d, ok := m.site(name)
		if !ok || d.Route != Direct || r.o.Fake == nil {
			return false
		}
		switch q.Type {
		case dnsmessage.TypeA, dnsmessage.TypeALL:
			ip = r.o.Fake.addr(name)
		case dnsmessage.TypeAAAA, dnsmessage.TypeHTTPS, dnsmessage.TypeSVCB:
			// No answer: IPv6 or the addresses an HTTPS record may carry
			// would go around the placeholder.
		default:
			return false
		}
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true, RCode: rcode,
	})
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(q) != nil || b.StartAnswers() != nil {
		return false
	}
	if ip.IsValid() {
		if b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: fakeTTL}, dnsmessage.AResource{A: ip.As4()}) != nil {
			return false
		}
	}
	msg, err := b.Finish()
	if err != nil {
		return false
	}
	r.writeOut(udpPackets(p.key.dst, p.key.src, msg, r.mtu, 0, uint16(r.udp.id.Add(1))), 0)
	return true
}

// dnsSnoop notes the addresses in a DNS answer from the VPN.
func (r *Router) dnsSnoop(payload []byte) {
	var ps dnsmessage.Parser
	h, err := ps.Start(payload)
	if err != nil || !h.Response || h.RCode != dnsmessage.RCodeSuccess {
		return
	}
	q, err := ps.Question()
	if err != nil {
		return
	}
	if err := ps.SkipAllQuestions(); err != nil {
		return
	}
	name := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")
	now := time.Now()
	for {
		ah, err := ps.AnswerHeader()
		if err != nil {
			return
		}
		var addr netip.Addr
		switch ah.Type {
		case dnsmessage.TypeA:
			a, err := ps.AResource()
			if err != nil {
				return
			}
			addr = netip.AddrFrom4(a.A)
		case dnsmessage.TypeAAAA:
			a, err := ps.AAAAResource()
			if err != nil {
				return
			}
			addr = netip.AddrFrom16(a.AAAA)
		default:
			if ps.SkipAnswer() != nil {
				return
			}
			continue
		}
		ttl := min(max(time.Duration(ah.TTL)*time.Second, hostMinTTL), hostMaxTTL)
		r.hmu.Lock()
		if len(r.hosts) < maxHosts {
			r.hosts[addr] = hostEntry{name, now.Add(ttl).UnixNano()}
		}
		r.hmu.Unlock()
	}
}

// expireHosts forgets names past their time.
func (r *Router) expireHosts(now time.Time) {
	r.hmu.Lock()
	defer r.hmu.Unlock()
	n := now.UnixNano()
	for a, e := range r.hosts {
		if e.exp < n {
			delete(r.hosts, a)
		}
	}
}

// --- resolving sites sent direct ---

type resolved struct {
	addrs []netip.Addr
	exp   time.Time
}

// resolveCached returns the addresses when they are known already.
func (r *Router) resolveCached(name string) ([]netip.Addr, bool) {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	c, ok := r.resolved[name]
	return c.addrs, ok && time.Now().Before(c.exp)
}

// resolve finds a site's IPv4 addresses on the physical network (cached for
// a minute: UDP sends one packet at a time).
func (r *Router) resolve(name string) []netip.Addr {
	r.rmu.Lock()
	if c, ok := r.resolved[name]; ok && time.Now().Before(c.exp) {
		r.rmu.Unlock()
		return c.addrs
	}
	r.rmu.Unlock()
	if r.o.Resolver == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
	defer cancel()
	ips, err := r.o.Resolver.LookupNetIP(ctx, "ip4", name)
	var out []netip.Addr
	for _, ip := range ips {
		if ip = ip.Unmap(); ip.Is4() && !isFake(ip) {
			out = append(out, ip)
		}
	}
	ttl := time.Minute
	if err != nil || len(out) == 0 {
		ttl = 5 * time.Second
	}
	r.rmu.Lock()
	if len(r.resolved) > 4096 {
		clear(r.resolved)
	}
	r.resolved[name] = resolved{out, time.Now().Add(ttl)}
	r.rmu.Unlock()
	return out
}

// --- encrypted DNS of browsers ---

// Browsers switch to encrypted DNS (DoH) on their own when the system's DNS
// server offers it (1.1.1.1 does), and then never ask the system: rules by
// name would see nothing. While such rules exist, HTTPS and DNS-over-TLS to
// the tunnel's DNS servers are refused, and browsers fall back to plain DNS
// at once.
func (r *Router) blockDoH(b []byte, p *pkt) bool {
	port := p.key.dst.Port()
	if port != 443 && port != 853 {
		return false
	}
	found := false
	for _, a := range r.o.DNS {
		if a == p.key.dst.Addr() {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	if p.key.proto == protoTCP && p.syn {
		r.writeOut([][]byte{tcpReset(b, p)}, 0)
	}
	return true
}

// tcpReset builds the reset answering a SYN.
func tcpReset(b []byte, p *pkt) []byte {
	t := b[p.ihl:]
	seq := binary.BigEndian.Uint32(t[4:8])
	out := make([]byte, 40)
	out[0] = 0x45
	binary.BigEndian.PutUint16(out[2:], 40)
	out[8] = 64
	out[9] = protoTCP
	src, dst := p.key.dst.Addr().As4(), p.key.src.Addr().As4()
	copy(out[12:16], src[:])
	copy(out[16:20], dst[:])
	binary.BigEndian.PutUint16(out[10:], checksum(out[:20], 0))
	h := out[20:]
	binary.BigEndian.PutUint16(h[0:], p.key.dst.Port())
	binary.BigEndian.PutUint16(h[2:], p.key.src.Port())
	binary.BigEndian.PutUint32(h[8:], seq+1)
	h[12] = 5 << 4
	h[13] = 0x14 // RST, ACK
	var ps uint32
	for i := 0; i < 4; i += 2 {
		ps += uint32(src[i])<<8 | uint32(src[i+1])
		ps += uint32(dst[i])<<8 | uint32(dst[i+1])
	}
	ps += protoTCP + 20
	binary.BigEndian.PutUint16(h[16:], checksum(h, ps))
	return out
}
