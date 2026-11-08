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
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/Jetvac/turn-vk-client/core/engine"
	"github.com/Jetvac/turn-vk-client/core/link"
	"github.com/Jetvac/turn-vk-client/core/netx"
	"github.com/Jetvac/turn-vk-client/core/wrap"
)

func main() {
	linkS := flag.String("link", "", "wdtt:// link")
	sessions := flag.Int("sessions", 16, "parallel sessions (TURN allocations)")
	obfs := flag.String("obfs", "audio", "RTP disguise: audio or video")
	devID := flag.String("device-id", "", "device ID (default: derived from the host name)")
	turnS := flag.String("turn", "", "TURN server host:port (default: the ones VK returns)")
	dns := flag.String("dns", strings.Join(netx.DefaultDNS, ","), "DNS servers for VK and TURN names (empty: system)")
	socks := flag.String("socks", "127.0.0.1:1080", "SOCKS5 proxy address")
	test := flag.Bool("test", false, "check the tunnel (exit IP, DNS) and exit")
	download := flag.String("download", "", "download a URL through the tunnel, print the speed and exit")
	hold := flag.Duration("hold", 0, "with -test: keep requesting once a second for this long")
	verbose := flag.Bool("v", false, "verbose log")
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	if *linkS == "" {
		*linkS = os.Getenv("TURNVK_LINK")
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

	var tnet *netstack.Net
	e, err := engine.New(engine.Config{
		Link: l, DeviceID: *devID, Sessions: *sessions, Mode: wrap.ParseMode(*obfs), TURNServer: *turnS,
		Net:     &netx.Net{DNS: dnsList},
		Captcha: newCaptchaSolver(),
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
		tnet = n
		return td, err
	})
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	log.Printf("tunnel up in %v", time.Since(t0).Round(time.Millisecond))
	defer e.Stop()

	switch {
	case *test || *download != "":
		code := runTests(ctx, e, tnet, *test, *hold, *download)
		e.Stop()
		os.Exit(code)
	default:
		go serveSOCKS(ctx, *socks, tnet)
		log.Printf("SOCKS5 proxy on %s", *socks)
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
