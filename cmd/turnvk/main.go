// Command turnvk is the desktop client. In proxy mode (the default, no
// administrator rights needed) it runs the tunnel in-process and offers a
// SOCKS5 proxy; -test and -download check the tunnel and exit.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/Jetvac/turn-vk-client/core/engine"
	"github.com/Jetvac/turn-vk-client/core/link"
	"github.com/Jetvac/turn-vk-client/core/netx"
	"github.com/Jetvac/turn-vk-client/core/session"
	"github.com/Jetvac/turn-vk-client/core/wrap"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	linkS := flag.String("link", "", "wdtt:// link")
	sessions := flag.Int("sessions", 16, "parallel sessions (TURN allocations)")
	obfs := flag.String("obfs", "audio", "RTP disguise: audio or video")
	devID := flag.String("device-id", "", "device ID (default: derived from the host name)")
	turnS := flag.String("turn", "", "TURN server host:port (default: the ones VK returns)")
	dns := flag.String("dns", strings.Join(netx.DefaultDNS, ","), "DNS servers for VK and TURN names (empty: system)")
	socks := flag.String("socks", "127.0.0.1:1080", "SOCKS5 proxy address")
	socksAuthS := flag.String("socks-auth", os.Getenv("TURNVK_SOCKS_AUTH"), "SOCKS5 user:password (default: a random password, printed at start; none: no password, any program can use the proxy)")
	test := flag.Bool("test", false, "check the tunnel (exit IP, DNS) and exit")
	download := flag.String("download", "", "download a URL through the tunnel, print the speed and exit")
	hold := flag.Duration("hold", 0, "with -test: keep requesting once a second for this long")
	verbose := flag.Bool("v", false, "verbose log")
	pingHost := flag.String("ping", "", "with -test or -download: ICMP ping this address through the tunnel (e.g. the server's tunnel address)")
	pings := flag.Int("pings", 50, "number of pings, 5 per second")
	stats := flag.Bool("stats", false, "print speed and route round trips every second")
	noStats := flag.Bool("no-server-stats", false, "send the server no statistics of the connection")
	allRoutes := flag.Bool("all-routes", false, "keep every route open (no light tier while traffic is light); on for -download and -upload")
	upload := flag.Int("upload", 0, "upload this many MB through the tunnel, print the speed and exit")
	uploadURL := flag.String("upload-url", "https://speed.cloudflare.com/__up", "where -upload sends its data (HTTP POST)")
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	if *linkS == "" {
		*linkS = os.Getenv("TURNVK_LINK")
	}
	socksAuth, err := parseSocksAuth(*socksAuthS)
	if err != nil {
		log.Fatal(err)
	}
	l, err := link.Parse(*linkS)
	if err != nil {
		log.Fatalf("link: %v", err)
	}
	if *devID == "" {
		h, _ := os.Hostname()
		sum := sha256.Sum256([]byte("turnvk|" + h))
		*devID = "pc-" + hex.EncodeToString(sum[:8])
	}
	var dnsList []string
	for _, s := range strings.Split(*dns, ",") {
		if s = strings.TrimSpace(s); s != "" {
			if !strings.Contains(s, ":") {
				s += ":53"
			}
			dnsList = append(dnsList, s)
		}
	}

	tcpT, err := parseTCPTuning(os.Getenv("TURNVK_TCP"))
	if err != nil {
		log.Fatal(err)
	}
	var tnet *netstack.Net
	e, err := engine.New(engine.Config{
		Link: l, DeviceID: *devID, Sessions: *sessions, Mode: wrap.ParseMode(*obfs), TURNServer: *turnS,
		Net:     &netx.Net{DNS: dnsList},
		Captcha: newCaptchaSolver(),
		VKCache: vkCacheFile(),
		// TURNVK_SCORE=off: plain rotation over VK's TURN servers (comparisons).
		NoRelayScoring: os.Getenv("TURNVK_SCORE") == "off",
		NoStats:        *noStats,
		// Speed tests measure every route from the first second.
		AllRoutes: *allRoutes || *download != "" || *upload > 0,
		Client:    "turnvk-cli " + version + " " + runtime.GOOS,
		Logf: func(f string, a ...any) {
			log.Printf(f, a...)
		},
		OnStatus: func(s engine.Status) {
			if *verbose {
				log.Printf("status: %s sessions=%d/%d rx=%d tx=%d %s", s.State, s.Sessions, s.Target, s.RxBytes, s.TxBytes, s.LastError)
			}
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	t0 := time.Now()
	err = e.Start(ctx, func(c *engine.WGConfig) (tun.Device, error) {
		dnsAddrs := c.DNS
		if len(dnsAddrs) == 0 {
			dnsAddrs = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
		}
		td, n, err := netstack.CreateNetTUN([]netip.Addr{c.Address.Addr()}, dnsAddrs, c.MTU)
		if err != nil {
			return nil, err
		}
		tnet = n
		if os.Getenv("TURNVK_TCP") == "off" {
			log.Printf("TCP: gVisor's defaults")
		} else if err := tuneTCP(n, tcpT); err != nil {
			log.Printf("TCP tuning: %v (using gVisor's defaults)", err)
		} else if *verbose || os.Getenv("TURNVK_TCP") != "" {
			log.Printf("TCP: %v", tcpT)
		}
		return td, nil
	})
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	log.Printf("tunnel up in %v", time.Since(t0).Round(time.Millisecond))
	defer e.Stop()

	switch {
	case *test || *download != "" || *upload > 0:
		if *stats {
			go printStats(ctx, e)
		}
		var pr chan string
		if *pingHost != "" {
			pr = make(chan string, 1)
			go func() { pr <- pingStats(ctx, tnet, *pingHost, *pings, *verbose) }()
		}
		code := runTests(ctx, e, tnet, *test, *hold, *download)
		if *upload > 0 && runUpload(ctx, e, tnet, *upload, *uploadURL) != 0 {
			code = 1
		}
		if pr != nil {
			fmt.Println(<-pr)
		}
		if *stats {
			printRoutes(e)
		}
		e.Stop()
		if *stats {
			freed, gone, failed := session.ReleaseStats()
			fmt.Printf("RELEASED freed=%d already=%d failed=%d\n", freed, gone, failed)
		}
		os.Exit(code)
	default:
		go serveSOCKS(ctx, *socks, socksAuth, tnet.DialContext)
		if socksAuth.user == "" {
			log.Printf("SOCKS5 proxy on %s, no password: any program on this computer can use it", *socks)
		} else {
			log.Printf("SOCKS5 proxy on %s, user %s, password %s (socks5h://%s:%s@%s)", *socks, socksAuth.user, socksAuth.pass, socksAuth.user, socksAuth.pass, *socks)
		}
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-e.Done():
				log.Fatalf("stopped: %v", e.Err())
			case <-t.C:
				s := e.Status()
				log.Printf("%s: %d/%d sessions, ↓%s ↑%s", s.State, s.Sessions, s.Target, size(s.RxBytes), size(s.TxBytes))
			}
		}
	}
}

func runTests(ctx context.Context, e *engine.Engine, tnet *netstack.Net, test bool, hold time.Duration, dl string) int {
	client := &http.Client{Transport: &http.Transport{DialContext: tnet.DialContext}, Timeout: 120 * time.Second}
	fails := 0
	if test {
		t := time.Now()
		ip, err := exitIP(ctx, client)
		if err != nil {
			fmt.Println("EXIT_IP_FAIL", err)
			fails++
		} else {
			fmt.Printf("EXIT_IP %s (%v)\n", ip, time.Since(t).Round(time.Millisecond))
		}
		if addrs, err := tnet.LookupContextHost(ctx, "example.com"); err == nil && len(addrs) > 0 {
			fmt.Println("DNS_OK", addrs[0])
		} else {
			fmt.Println("DNS_FAIL", err)
			fails++
		}
	}
	if dl != "" {
		// Let the other sessions come up first.
		for i := 0; i < 20 && e.Status().Sessions < e.Status().Target; i++ {
			time.Sleep(500 * time.Millisecond)
		}
		t := time.Now()
		resp, err := client.Get(dl)
		if err != nil {
			fmt.Println("DOWNLOAD_FAIL", err)
			return 1
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			fmt.Println("DOWNLOAD_FAIL HTTP", resp.StatusCode)
			return 1
		}
		n, err := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		d := time.Since(t)
		fmt.Printf("DOWNLOAD %d MB in %v = %.1f Mbit/s (sessions %d) err=%v\n", n>>20, d.Round(time.Millisecond), float64(n*8)/d.Seconds()/1e6, e.Status().Sessions, err)
	}
	if hold > 0 {
		hc := &http.Client{Transport: &http.Transport{DialContext: tnet.DialContext, DisableKeepAlives: true}, Timeout: 5 * time.Second}
		ok, bad := 0, 0
		var worst time.Duration
		end := time.Now().Add(hold)
		for time.Now().Before(end) && ctx.Err() == nil {
			t := time.Now()
			if _, err := exitIP(ctx, hc); err != nil {
				bad++
				log.Printf("hold: %v", err)
			} else {
				ok++
				worst = max(worst, time.Since(t))
			}
			if d := time.Second - time.Since(t); d > 0 {
				time.Sleep(d)
			}
		}
		s := e.Status()
		fmt.Printf("HOLD ok=%d fail=%d worst=%v sessions=%d reconnects=%d\n", ok, bad, worst.Round(time.Millisecond), s.Sessions, s.Reconnects)
		fails += bad
	}
	if fails > 0 {
		return 1
	}
	return 0
}

func exitIP(ctx context.Context, c *http.Client) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://one.one.one.one/cdn-cgi/trace", nil)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "ip=") {
			return strings.TrimPrefix(l, "ip="), nil
		}
	}
	return "", fmt.Errorf("no ip in the answer")
}

func size(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%d KB", n>>10)
}

var _ = net.IPv4len

// vkCacheFile is where VK guest tokens are kept between runs, so that a
// restart does not bring up a captcha.
// printRoutes prints one ROUTE line per open route: its VK TURN server,
// round trip, the server's packets it received and lost, and its upload
// pacing.
func printRoutes(e *engine.Engine) {
	s := e.Status()
	fmt.Printf("ROUTES open=%d target=%d replaced=%d\n", s.Sessions, s.Target, s.Reconnects)
	for _, p := range s.Paths {
		loss := 0.0
		if p.RxPackets+p.Lost > 0 {
			loss = 100 * float64(p.Lost) / float64(p.RxPackets+p.Lost)
		}
		fmt.Printf("ROUTE %d server=%s rtt=%d rx=%d lost=%.2f%% up_rate=%.1f up_loss=%.2f%% fresh=%v\n",
			p.ID, p.Server, p.RTT, p.RxPackets, loss, float64(p.UpRate)*8/1e6, 100*p.UpLoss, p.Fresh)
	}
}

func vkCacheFile() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "turnvk", "vk-guests.json")
}

// pingStats pings host through the tunnel n times, 5 per second, and
// returns the round-trip summary.
func pingStats(ctx context.Context, tnet *netstack.Net, host string, n int, each bool) string {
	c, err := tnet.DialContext(ctx, "ping4", host)
	if err != nil {
		return "PING_FAIL " + err.Error()
	}
	defer c.Close()
	var rtts []time.Duration
	buf := make([]byte, 1500)
	for i := 0; i < n && ctx.Err() == nil; i++ {
		t := time.Now()
		msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 1234, Seq: i, Data: []byte("turnvk-ping-turnvk-ping")}}
		b, _ := msg.Marshal(nil)
		if _, err := c.Write(b); err != nil {
			continue
		}
		_ = c.SetReadDeadline(t.Add(2 * time.Second))
		for {
			m, err := c.Read(buf)
			if err != nil {
				break
			}
			r, err := icmp.ParseMessage(1, buf[:m])
			if err != nil || r.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			if e, ok := r.Body.(*icmp.Echo); ok && e.Seq == i {
				rtts = append(rtts, time.Since(t))
				if each {
					fmt.Printf("PINGSAMPLE %s %d %.1f\n", t.Format("15:04:05.000"), i, float64(time.Since(t))/1e6)
				}
				break
			}
		}
		if d := 200*time.Millisecond - time.Since(t); d > 0 {
			time.Sleep(d)
		}
	}
	if len(rtts) == 0 {
		return fmt.Sprintf("PING %s lost %d/%d", host, n, n)
	}
	sorted := append([]time.Duration(nil), rtts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var sum time.Duration
	for _, r := range rtts {
		sum += r
	}
	ms := func(d time.Duration) string { return fmt.Sprintf("%.1f", float64(d)/1e6) }
	return fmt.Sprintf("PING %s min=%s avg=%s p50=%s p95=%s max=%s ms, lost %d/%d", host,
		ms(sorted[0]), ms(sum/time.Duration(len(rtts))), ms(sorted[len(sorted)/2]), ms(sorted[len(sorted)*95/100]), ms(sorted[len(sorted)-1]), n-len(rtts), n)
}

// printStats prints the speed and the routes' round trips every second.
func printStats(ctx context.Context, e *engine.Engine) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	prev := e.Status()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s := e.Status()
		var rtts []int
		fresh := 0
		var got, lost, got0, lost0 uint64
		for _, p := range prev.Paths {
			got0 += p.RxPackets
			lost0 += p.Lost
		}
		for _, p := range s.Paths {
			got += p.RxPackets
			lost += p.Lost
			if p.RTT > 0 {
				rtts = append(rtts, p.RTT)
			}
			if p.Fresh {
				fresh++
			}
		}
		sort.Ints(rtts)
		med, worst := 0, 0
		if len(rtts) > 0 {
			med, worst = rtts[len(rtts)/2], rtts[len(rtts)-1]
		}
		upRate, upLoss, upQ, upN := 0, 0.0, 0, 0
		for _, p := range s.Paths {
			if p.UpRate > 0 {
				upRate += p.UpRate
				upLoss += p.UpLoss
				upQ += p.UpQueue
				upN++
			}
		}
		up := ""
		if upN > 0 {
			up = fmt.Sprintf(" | up pace=%.1f Mbit/s loss=%.1f%% queue=%d ms", float64(upRate)*8/1e6, upLoss*100/float64(upN), upQ/upN)
		}
		loss := 0.0
		if dg, dl := int64(got-got0), int64(lost-lost0); dg+dl > 0 && dl >= 0 {
			loss = float64(dl) * 100 / float64(dg+dl)
		}
		fmt.Printf("STATS down=%.1f up=%.2f Mbit/s routes=%d/%d rtt median=%d worst=%d ms loss=%.1f%%%s\n",
			float64(s.RxBytes-prev.RxBytes)*8/1e6, float64(s.TxBytes-prev.TxBytes)*8/1e6, fresh, len(s.Paths), med, worst, loss, up)
		prev = s
	}
}

// runUpload sends mb megabytes to a speed test endpoint through the tunnel.
func runUpload(ctx context.Context, e *engine.Engine, tnet *netstack.Net, mb int, url string) int {
	for i := 0; i < 20 && e.Status().Sessions < e.Status().Target; i++ {
		time.Sleep(500 * time.Millisecond)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: tnet.DialContext}, Timeout: 300 * time.Second}
	body := strings.NewReader(strings.Repeat("turnvk-upload-test-", mb<<20/19+1)[:mb<<20])
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	t := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("UPLOAD_FAIL", err)
		return 1
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	d := time.Since(t)
	if resp.StatusCode != http.StatusOK {
		fmt.Println("UPLOAD_FAIL HTTP", resp.StatusCode)
		return 1
	}
	fmt.Printf("UPLOAD %d MB in %v = %.1f Mbit/s (sessions %d)\n", mb, d.Round(time.Millisecond), float64(mb<<20)*8/d.Seconds()/1e6, e.Status().Sessions)
	return 0
}
