package split

// Sites sent direct that do not open are tried through the VPN: a site
// blocked on the physical network but missing from the user's rules and
// lists still opens, a little later. A TCP connection to a web port is
// accepted inside TurnVK (as one waiting for its name), connected direct,
// and, when that fails — no answer, a refusal, or a TLS server that drops
// the hello or answers nothing (how blocking usually looks) — opened again
// through the VPN with the same first bytes. Only TLS is checked for an
// answer: its hello may be sent twice, a plain HTTP request may not.
//
// The site is then remembered for a while (its next connections go
// straight through the VPN) and offered to the user as a rule.

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/publicsuffix"
)

const (
	// retryWait: how long a direct try may take to connect, and then to
	// answer a TLS hello.
	retryWait = 5 * time.Second
	// failTTL: how long a site that failed direct goes straight through
	// the VPN (and is offered as a rule).
	failTTL     = 30 * time.Minute
	maxFailures = 512

	whyRetried = "не открылся напрямую — через VPN"
	whyFailed  = "раньше не открылся напрямую — через VPN"
)

// Failure is a site that did not open direct.
type Failure struct {
	Host string `json:"host,omitempty"`
	Addr string `json:"addr"`
	// App: the program (Android: the package) that opened it.
	App string `json:"app,omitempty"`
	// Why: what went wrong direct.
	Why string `json:"why"`
	// Rule: the site rule to offer ("" when the name is not known).
	Rule  string `json:"rule,omitempty"`
	Count int    `json:"count"`
	Last  int64  `json:"last"` // unix ms
	// OK: it opened through the VPN.
	OK bool `json:"ok"`
}

// directErr says in a few words what went wrong direct.
type directErr struct {
	why string
	err error
}

func (e *directErr) Error() string { return e.why }
func (e *directErr) Unwrap() error { return e.err }

func dialWhy(err error) string {
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout():
		return "нет ответа"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "соединение отклонено"
	case errors.Is(err, syscall.ECONNRESET):
		return "соединение сброшено"
	}
	return "не соединился"
}

func isTLSHello(b []byte) bool { return len(b) > 5 && b[0] == 0x16 && b[1] == 3 }

// tryDirect connects to dst on the physical network and sends head; check:
// a TLS hello must be answered within retryWait (first: the answer).
func (r *Router) tryDirect(dst netip.AddrPort, head []byte, check bool) (out net.Conn, first []byte, err error) {
	timeout := 10 * time.Second
	if check {
		timeout = retryWait
	}
	dl := net.Dialer{Timeout: timeout, Control: r.control, KeepAlive: 30 * time.Second}
	out, err = r.dialTCP(&dl, dst)
	if err != nil {
		return nil, nil, &directErr{dialWhy(err), err}
	}
	if len(head) > 0 {
		if _, err := out.Write(head); err != nil {
			out.Close()
			return nil, nil, &directErr{"соединение сброшено", err}
		}
	}
	if !check || !isTLSHello(head) {
		return out, nil, nil
	}
	_ = out.SetReadDeadline(time.Now().Add(retryWait))
	buf := make([]byte, 32<<10)
	for {
		n, err := out.Read(buf)
		if n > 0 {
			_ = out.SetReadDeadline(time.Time{})
			return out, buf[:n], nil
		}
		if err != nil {
			out.Close()
			why := "сброс после приветствия TLS"
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				why = "нет ответа на приветствие TLS"
			} else if errors.Is(err, io.EOF) {
				why = "закрыто после приветствия TLS"
			}
			return nil, nil, &directErr{why, err}
		}
	}
}

// dialVPNFor opens the flow's connection through the VPN: from the
// program's own address and port, or, for a placeholder, to the site's
// address found through the VPN's DNS.
func (r *Router) dialVPNFor(f *flow, src, dst netip.AddrPort) (net.Conn, error) {
	if !isFake(dst.Addr()) {
		return r.relayDial(f, src, dst)
	}
	name := r.o.Fake.Name(dst.Addr())
	if name == "" {
		return nil, errors.New("unknown placeholder " + dst.Addr().String())
	}
	ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
	defer cancel()
	addrs, err := r.VPNResolver().LookupNetIP(ctx, "ip4", name)
	if err != nil {
		return nil, err
	}
	last := errors.New("no address for " + name)
	n := 0
	for _, a := range addrs {
		if a = a.Unmap(); !a.Is4() || isFake(a) {
			continue
		}
		if n++; n > 3 {
			break
		}
		h := &flow{route: VPN, why: whyRetried, path: f.path, pid: f.pid, host: name, start: time.Now(), hidden: true}
		c, err := r.dialVPN(ctx, netip.AddrPortFrom(a, dst.Port()), h)
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// openSniffed opens a connection accepted inside TurnVK once its first
// bytes (head) are read: direct or through the VPN, as its name and the
// rules say, with head sent on. first: the far end's first bytes, read
// already (a direct try's answer).
func (r *Router) openSniffed(f *flow, src, dst netip.AddrPort, host string, head []byte) (out net.Conn, first []byte, err error) {
	d := f.prelim
	if !isFake(dst.Addr()) {
		d = r.decideSniffed(f, host, f.prelim)
	}
	if d.Route == Direct && f.viaVPN {
		d = Decision{VPN, whyFailed}
	}
	if d.Route == Direct {
		r.settle(f, host, d)
		retry := f.retry && r.m.Load().retry
		out, first, err = r.tryDirect(dst, head, retry)
		if err == nil || !retry {
			return out, first, err
		}
		failed := err
		r.settle(f, host, Decision{VPN, whyRetried})
		out, err = r.dialVPNFor(f, src, dst)
		r.noteFailed(f, host, failed, err == nil)
		if err != nil {
			return nil, nil, failed
		}
	} else {
		r.settle(f, host, d)
		out, err = r.dialVPNFor(f, src, dst)
		if err != nil {
			return nil, nil, err
		}
	}
	if len(head) > 0 {
		if _, err := out.Write(head); err != nil {
			out.Close()
			return nil, nil, err
		}
	}
	return out, nil, nil
}

// --- the sites that failed direct ---

func failKeys(host string, dst netip.Addr) []string {
	var k []string
	if host != "" {
		k = append(k, "h:"+strings.ToLower(strings.TrimSuffix(host, ".")))
	}
	if dst.IsValid() && !isFake(dst) {
		k = append(k, "a:"+dst.String())
	}
	return k
}

// failedBefore: the site (by name, else by address) did not open direct
// lately but did through the VPN.
func (r *Router) failedBefore(host string, dst netip.Addr) bool {
	now := time.Now().UnixMilli()
	r.fmu.Lock()
	defer r.fmu.Unlock()
	for _, k := range failKeys(host, dst) {
		if x := r.failed[k]; x != nil && x.OK && now-x.Last < failTTL.Milliseconds() {
			return true
		}
		if host != "" {
			break // by name only: other sites share addresses
		}
	}
	return false
}

func (r *Router) noteFailed(f *flow, host string, err error, ok bool) {
	dst := f.key.dst.Addr()
	if host == "" && isFake(dst) {
		host = r.o.Fake.Name(dst)
	}
	why := err.Error()
	if de := (*directErr)(nil); !errors.As(err, &de) {
		why = "не соединился"
	}
	addr := f.key.dst.String()
	if isFake(dst) {
		addr = ""
	}
	r.fmu.Lock()
	if r.failed == nil || len(r.failed) > maxFailures {
		r.failed = map[string]*Failure{}
	}
	keys := failKeys(host, dst)
	var x *Failure
	for _, k := range keys {
		if x = r.failed[k]; x != nil {
			break
		}
	}
	if x == nil {
		x = &Failure{Host: host, Addr: addr, App: baseName(f.path)}
		if host != "" {
			x.Rule = siteRule(host)
		}
	}
	x.Why, x.OK, x.Last = why, ok, time.Now().UnixMilli()
	x.Count++
	for _, k := range keys {
		r.failed[k] = x
	}
	r.fmu.Unlock()
	name := host
	if name == "" {
		name = addr
	}
	if ok {
		r.o.Logf("split: %s did not open direct (%s), opened through the VPN", name, why)
	} else {
		r.o.Logf("split: %s did not open direct (%s) nor through the VPN", name, why)
	}
}

// siteRule: the site to offer a rule for (the registered domain:
// "rr3.googlevideo.com" -> "googlevideo.com").
func siteRule(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		host = d
	}
	if u, err := NormalizeDomain(host); err == nil {
		return u
	}
	return host
}

// Failures lists the sites that did not open direct lately, most recent
// first, leaving out those a rule now sends through the VPN.
func (r *Router) Failures() []Failure {
	m := r.m.Load()
	now := time.Now().UnixMilli()
	seen := map[*Failure]bool{}
	var out []Failure
	r.fmu.Lock()
	for _, x := range r.failed {
		if seen[x] || now-x.Last > failTTL.Milliseconds() {
			continue
		}
		seen[x] = true
		if x.Host != "" {
			if d, ok := m.site(x.Host); ok && d.Route == VPN {
				continue
			}
		}
		out = append(out, *x)
	}
	r.fmu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Last > out[j].Last })
	if len(out) > 30 {
		out = out[:30]
	}
	return out
}

// ForgetFailures clears the list (and lets those sites try direct again).
func (r *Router) ForgetFailures() {
	r.fmu.Lock()
	r.failed = nil
	r.fmu.Unlock()
}
