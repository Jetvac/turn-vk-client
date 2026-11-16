// Package diag builds the diagnostic report the apps copy for developers:
// the system, the settings, the engine's state and history, a few network
// checks and the recent log, with secrets taken out.
package diag

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Jetvac/turn-vk-client/core/engine"
	"github.com/Jetvac/turn-vk-client/core/link"
)

// Report is everything that goes into the text.
type Report struct {
	App      string   // "TurnVK Windows 0.3.1"
	System   []string // "key: value" lines from the platform
	Settings []string
	Link     string // the raw link: only a summary goes into the report
	Error    string // the last error the app showed
	Status   *engine.Status
	Diag     *engine.Diag
	Checks   []Check
	Log      []string
}

// MaxLog is how many log lines (the newest) go into the report.
const MaxLog = 400

// Text formats the report.
func (r *Report) Text() string {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	p("=== %s diagnostic report, %s ===", r.App, time.Now().Format("2006-01-02 15:04:05 -0700"))
	p("")
	p("[system]")
	for _, s := range r.System {
		p("%s", Redact(s))
	}
	p("")
	p("[settings]")
	for _, s := range r.Settings {
		p("%s", Redact(s))
	}
	p("server: %s", linkSummary(r.Link))
	if r.Error != "" {
		p("last error shown: %s", Redact(r.Error))
	}
	p("")
	r.status(p)
	r.diag(p)
	if len(r.Checks) > 0 {
		p("[checks]")
		for _, c := range r.Checks {
			mark := "FAIL"
			if c.OK {
				mark = "ok  "
			}
			p("%s %-34s %6s  %s", mark, c.Name, c.Took.Round(time.Millisecond), Redact(c.Result))
		}
		p("")
	}
	logs := r.Log
	if len(logs) > MaxLog {
		logs = logs[len(logs)-MaxLog:]
	}
	p("[log, last %d lines]", len(logs))
	for _, l := range logs {
		p("%s", Redact(l))
	}
	return b.String()
}

func (r *Report) status(p func(string, ...any)) {
	st := r.Status
	p("[connection]")
	if st == nil {
		p("not connected")
		p("")
		return
	}
	p("state: %s since %s", st.State, time.Unix(st.Since, 0).Format("15:04:05"))
	p("routes: %d of %d, protocol %s, average RTT %d ms, reconnects %d", st.Sessions, st.Target, orDash(st.Protocol), st.RTT, st.Reconnects)
	p("on the routes: in %s, out %s", size(st.RxBytes), size(st.TxBytes))
	if st.Captcha {
		p("VK is waiting for a captcha")
	}
	if st.LastError != "" {
		p("last engine error: %s", Redact(st.LastError))
	}
	// Routes grouped by TURN server.
	type agg struct {
		n, fresh    int
		rtt, rttN   int
		rxp, lost   uint64
		rate, rate1 int
	}
	by := map[string]*agg{}
	for _, ps := range st.Paths {
		a := by[ps.Server]
		if a == nil {
			a = &agg{}
			by[ps.Server] = a
		}
		a.n++
		if ps.Fresh {
			a.fresh++
		}
		if ps.RTT > 0 {
			a.rtt += ps.RTT
			a.rttN++
		}
		a.rxp += ps.RxPackets
		a.lost += ps.Lost
		if ps.UpRate > 0 {
			a.rate += ps.UpRate
			a.rate1++
		}
	}
	servers := make([]string, 0, len(by))
	for s := range by {
		servers = append(servers, s)
	}
	sort.Strings(servers)
	for _, s := range servers {
		a := by[s]
		line := fmt.Sprintf("  TURN %-22s routes %2d (answering %2d)", s, a.n, a.fresh)
		if a.rttN > 0 {
			line += fmt.Sprintf(", RTT %d ms", a.rtt/a.rttN)
		}
		if a.rxp+a.lost > 0 {
			line += fmt.Sprintf(", loss %.1f%%", 100*float64(a.lost)/float64(a.rxp+a.lost))
		}
		if a.rate1 > 0 {
			line += fmt.Sprintf(", upload pace %s/s", size(uint64(a.rate)))
		}
		p("%s", line)
	}
	p("")
}

func (r *Report) diag(p func(string, ...any)) {
	d := r.Diag
	if d == nil || d.Connected.IsZero() {
		return
	}
	p("[tunnel]")
	p("up since %s (%s), address %s, MTU %d, DNS %s", d.Connected.Format("15:04:05"), time.Since(d.Connected).Round(time.Second), d.Address, d.MTU, orDash(strings.Join(d.DNS, ", ")))
	p("server %s, %d VK call(s), protocol %s", d.Peer, d.Calls, orDash(d.Protocol))
	switch {
	case d.FirstHandshake == 0:
		p("WireGuard handshake: NONE: the server never answered")
	default:
		p("WireGuard handshake: first %s after connecting, last %s ago", d.FirstHandshake.Round(100*time.Millisecond), time.Since(d.LastHandshake).Round(time.Second))
	}
	p("through the tunnel: in %s, out %s", size(d.WGRx), size(d.WGTx))
	if len(d.Samples) > 0 {
		p("every 10 s (time, in, out, routes, packets lost):")
		for _, s := range d.Samples {
			p("  %s %10s %10s %3d %5d", s.At.Format("15:04:05"), size(s.Rx), size(s.Tx), s.Routes, s.Lost)
		}
	}
	p("")
}

// linkSummary describes a link without its secrets.
func linkSummary(raw string) string {
	if raw == "" {
		return "none"
	}
	l, err := link.Parse(raw)
	if err != nil {
		return "unusable link: " + Redact(err.Error())
	}
	key := "no (standard WDTT)"
	if len(l.ServerKey) == 32 {
		key = "yes (TurnVK)"
	}
	return fmt.Sprintf("%s, port %d, WireGuard port %d, %d VK call(s), server key: %s", l.Host, l.DTLSPort, l.WGPort, len(l.Hashes), key)
}

var (
	reLink  = regexp.MustCompile(`wdtt://\S+`)
	reVK    = regexp.MustCompile(`(?i)(vk\.com/call/join/|join/)[A-Za-z0-9_\-]+`)
	reToken = regexp.MustCompile(`(?i)(access_token|token|password|pass|key|sig|hash)=([^&\s"]+)`)
	reLong  = regexp.MustCompile(`[A-Za-z0-9+/_\-]{32,}={0,2}`)
)

// Redact takes secrets out of a line: links, VK call ids, tokens and any
// long key-like string.
func Redact(s string) string {
	s = reLink.ReplaceAllString(s, "wdtt://<hidden>")
	s = reVK.ReplaceAllString(s, "${1}<hidden>")
	s = reToken.ReplaceAllString(s, "$1=<hidden>")
	s = reLong.ReplaceAllString(s, "<hidden>")
	return s
}

// Check is one network check.
type Check struct {
	Name   string
	OK     bool
	Result string
	Took   time.Duration
}

// CheckOptions say which checks make sense.
type CheckOptions struct {
	// Tunnel: the checks' own connections go through the VPN (Windows,
	// where only the engine's sockets bypass it). The tunnel's checks run
	// only then.
	Tunnel bool
	DNS    []string // the tunnel's DNS servers
	Server string   // the WDTT server's host, to compare the exit address with
}

// RunChecks runs the checks in parallel, a few seconds each.
func RunChecks(ctx context.Context, o CheckOptions) []Check {
	type job struct {
		name string
		fn   func(context.Context) (string, error)
	}
	jobs := []job{
		{"DNS (system): vk.com", func(ctx context.Context) (string, error) { return lookup(ctx, net.DefaultResolver, "vk.com") }},
		{"HTTPS api.vk.com", func(ctx context.Context) (string, error) {
			return get(ctx, "https://api.vk.com/method/utils.getServerTime", 0)
		}},
	}
	if o.Tunnel {
		for _, d := range o.DNS {
			r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var dl net.Dialer
				return dl.DialContext(ctx, "udp", net.JoinHostPort(d, "53"))
			}}
			jobs = append(jobs, job{"DNS of the tunnel (" + d + "): google.com", func(ctx context.Context) (string, error) { return lookup(ctx, r, "google.com") }})
		}
		jobs = append(jobs,
			job{"HTTP connectivity (gstatic 204)", func(ctx context.Context) (string, error) {
				return get(ctx, "http://connectivitycheck.gstatic.com/generate_204", 204)
			}},
			job{"exit address (cloudflare trace)", func(ctx context.Context) (string, error) { return exitIP(ctx, o.Server) }},
			job{"HTTPS discord.com", func(ctx context.Context) (string, error) { return get(ctx, "https://discord.com/api/v9/gateway", 0) }},
			job{"HTTPS youtube.com", func(ctx context.Context) (string, error) { return get(ctx, "https://www.youtube.com/generate_204", 0) }},
		)
	}
	out := make([]Check, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			t := time.Now()
			res, err := j.fn(c)
			out[i] = Check{Name: j.name, OK: err == nil, Result: res, Took: time.Since(t)}
			if err != nil {
				out[i].Result = err.Error()
			}
		}()
	}
	wg.Wait()
	return out
}

func lookup(ctx context.Context, r *net.Resolver, host string) (string, error) {
	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		return "", err
	}
	if len(addrs) > 3 {
		addrs = addrs[:3]
	}
	return strings.Join(addrs, " "), nil
}

// client: fresh connections every time, no proxy from the environment.
var client = &http.Client{
	Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 6 * time.Second},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func get(ctx context.Context, url string, want int) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if want != 0 && resp.StatusCode != want {
		return "", fmt.Errorf("HTTP %d, expected %d", resp.StatusCode, want)
	}
	return fmt.Sprintf("HTTP %d", resp.StatusCode), nil
}

func exitIP(ctx context.Context, server string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	resp.Body.Close()
	ip, loc := "", ""
	for _, l := range strings.Split(string(body), "\n") {
		if v, ok := strings.CutPrefix(l, "ip="); ok {
			ip = v
		}
		if v, ok := strings.CutPrefix(l, "loc="); ok {
			loc = v
		}
	}
	if ip == "" {
		return "", fmt.Errorf("HTTP %d, no address in the answer", resp.StatusCode)
	}
	res := ip + " (" + loc + ")"
	if server != "" {
		if addrs, err := net.DefaultResolver.LookupHost(ctx, server); err == nil {
			same := false
			for _, a := range addrs {
				same = same || a == ip
			}
			if same {
				res += ", the WDTT server's address: traffic goes through the VPN"
			} else {
				res += ", not the WDTT server's address (the server may use another one for the internet, or traffic bypasses the VPN)"
			}
		}
	}
	return res, nil
}

func size(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
