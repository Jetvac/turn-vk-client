package split

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// A tiny protobuf writer for test files.
func pbVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}
func pbBytes(b []byte, num int, data []byte) []byte {
	b = pbVarint(b, uint64(num)<<3|2)
	b = pbVarint(b, uint64(len(data)))
	return append(b, data...)
}
func pbUint(b []byte, num int, v uint64) []byte {
	return pbVarint(pbVarint(b, uint64(num)<<3), v)
}

func geoipEntry(code string, cidrs ...string) []byte {
	e := pbBytes(nil, 1, []byte(code))
	for _, c := range cidrs {
		p := netip.MustParsePrefix(c)
		var x []byte
		x = pbBytes(x, 1, p.Addr().AsSlice())
		x = pbUint(x, 2, uint64(p.Bits()))
		e = pbBytes(e, 2, x)
	}
	return pbBytes(nil, 1, e)
}

type dom struct {
	typ uint64
	val string
}

func geositeEntry(code string, ds ...dom) []byte {
	e := pbBytes(nil, 1, []byte(code))
	for _, d := range ds {
		var x []byte
		if d.typ != 0 {
			x = pbUint(x, 1, d.typ)
		}
		x = pbBytes(x, 2, []byte(d.val))
		e = pbBytes(e, 2, x)
	}
	return pbBytes(nil, 1, e)
}

func writeLists(t *testing.T) string {
	dir := t.TempDir()
	var ip []byte
	ip = append(ip, geoipEntry("RU", "5.8.0.0/16", "77.88.0.0/18", "77.88.64.0/18", "2a02:6b8::/32")...)
	ip = append(ip, geoipEntry("DE", "5.9.0.0/16")...)
	ip = append(ip, geoipEntry("TELEGRAM", "149.154.160.0/20")...)
	var site []byte
	site = append(site, geositeEntry("YOUTUBE", dom{2, "youtube.com"}, dom{2, "ytimg.com"}, dom{3, "youtu.be"})...)
	site = append(site, geositeEntry("RU-BLOCKED", dom{2, "blocked.example"}, dom{0, "rutracker"}, dom{1, `^ex\d+\.test$`})...)
	site = append(site, geositeEntry("CATEGORY-RU", dom{2, "ru"})...)
	if err := os.WriteFile(filepath.Join(dir, GeoIPFile), ip, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, GeoSiteFile), site, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadLists(t *testing.T) {
	dir := writeLists(t)
	l, err := LoadLists(dir, []ListRule{{List: "geoip:ru"}, {List: "geoip:telegram"}, {List: "geosite:youtube"}, {List: "geosite:ru-blocked"}, {List: "geoip:de", Off: true}, {List: "geosite:nope"}})
	if err != nil {
		t.Fatal(err)
	}
	if l.Has("geoip:de") || l.Has("geosite:nope") || !l.Has("geoip:ru") {
		t.Fatalf("lists %v %v", l.IP, l.Site)
	}
	ru := l.IP["geoip:ru"]
	if ru.Len() != 2 { // the two /18s merge; IPv6 is left out
		t.Fatalf("ranges %v", ru.r)
	}
	for a, want := range map[string]bool{"5.8.1.1": true, "77.88.127.255": true, "77.88.128.0": false, "5.9.0.1": false, "1.1.1.1": false} {
		if ru.Contains(netip.MustParseAddr(a)) != want {
			t.Errorf("ru %s: %v", a, !want)
		}
	}
	yt, rb := l.Site["geosite:youtube"], l.Site["geosite:ru-blocked"]
	for n, want := range map[string]bool{"youtube.com": true, "WWW.YouTube.com.": true, "i.ytimg.com": true, "youtu.be": true, "x.youtu.be": false, "notyoutube.com": false} {
		if yt.Match(n) != want {
			t.Errorf("youtube %s: %v", n, !want)
		}
	}
	for n, want := range map[string]bool{"a.blocked.example": true, "rutracker.org": true, "ex12.test": true, "ex.test": false} {
		if rb.Match(n) != want {
			t.Errorf("ru-blocked %s: %v", n, !want)
		}
	}
	names, err := ListNames(filepath.Join(dir, GeoSiteFile))
	if err != nil || !slices.Equal(names, []string{"category-ru", "ru-blocked", "youtube"}) {
		t.Fatalf("names %v %v", names, err)
	}
	// Not downloaded yet: no lists, an error that says so.
	if l, err := LoadLists(t.TempDir(), []ListRule{{List: "geoip:ru"}}); err == nil || l.Has("geoip:ru") {
		t.Fatal("a missing file")
	}
	// A broken file.
	os.WriteFile(filepath.Join(dir, GeoIPFile), []byte{0x0a, 0xff, 0xff}, 0o644)
	if _, err := LoadLists(dir, []ListRule{{List: "geoip:ru"}}); err == nil {
		t.Fatal("a broken file loaded")
	}
}

func TestNormalizeList(t *testing.T) {
	for in, want := range map[string]string{"geoip:RU": "geoip:ru", " geosite:category-ads-all ": "geosite:category-ads-all"} {
		if got, err := NormalizeList(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"ru", "geo:ru", "geoip:", "geosite:a b"} {
		if _, err := NormalizeList(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestListDecisions(t *testing.T) {
	dir := writeLists(t)
	r := Rules{On: true, Default: VPN, LAN: true,
		Apps:    []AppRule{{Path: `C:\Games\game.exe`, Route: VPN}, {Path: `C:\Apps\torrent.exe`, Route: Direct}},
		Domains: []DomainRule{{Domain: "music.youtube.com", Route: Direct}},
		Lists: []ListRule{{List: "geoip:ru", Route: Direct}, {List: "geoip:telegram", Route: VPN},
			{List: "geosite:youtube", Route: VPN}, {List: "geosite:category-ru", Route: Direct}, {List: "geosite:ru-blocked", Route: VPN}}}
	l, err := LoadLists(dir, r.Lists)
	if err != nil {
		t.Fatal(err)
	}
	m := newMatcher(r, nil, l)
	ru, other := netip.MustParseAddr("5.8.1.1"), netip.MustParseAddr("8.8.8.8")
	game, torrent, browser := &Proc{Path: `C:\Games\game.exe`}, &Proc{Path: `C:\Apps\torrent.exe`}, &Proc{Path: `C:\b.exe`}
	for _, c := range []struct {
		dst   netip.Addr
		host  string
		p     *Proc
		route Route
		why   string
	}{
		{ru, "", browser, Direct, "список geoip:ru"},
		{ru, "", game, VPN, "правило для game.exe"}, // a program's own rule beats a country
		{other, "", browser, VPN, "остальные программы"},
		{other, "www.youtube.com", torrent, VPN, "список geosite:youtube"}, // sites beat programs
		{other, "music.youtube.com", browser, Direct, "сайт music.youtube.com"},
		{ru, "rutracker.ru", browser, VPN, "список geosite:ru-blocked"}, // two lists: the VPN wins
		{other, "mail.ru", game, Direct, "список geosite:category-ru"},
		{netip.MustParseAddr("149.154.167.1"), "", browser, VPN, "список geoip:telegram"},
	} {
		d := m.decide(c.dst, c.host, c.p)
		if d.Route != c.route || d.Why != c.why {
			t.Errorf("%s %s %s: %+v", c.dst, c.host, c.p.Path, d)
		}
	}
	if !m.byName || !m.directSites || !m.anyDirect {
		t.Fatal("flags")
	}
	// Lists not loaded: the rules about them do nothing.
	if d := newMatcher(r, nil, nil).decide(ru, "", browser); d.Route != VPN {
		t.Fatalf("no lists: %+v", d)
	}
}

// A site list sending sites direct answers DNS with placeholders.
func TestSiteListDNS(t *testing.T) {
	dir := writeLists(t)
	rules := Rules{On: true, Default: VPN, Lists: []ListRule{{List: "geosite:category-ru", Route: Direct}}}
	l, _ := LoadLists(dir, rules.Lists)
	g := newRig(t, rules, withSites, func(o *Options) { o.Lists = l })
	a := g.ask(t, "yandex.ru", dnsmessage.TypeA)
	if a == nil || len(a.Answers) != 1 || !isFake(netip.AddrFrom4(a.Answers[0].Body.(*dnsmessage.AResource).A)) {
		t.Fatalf("no placeholder: %+v", a)
	}
	if g.ask(t, "example.com", dnsmessage.TypeA) != nil {
		t.Fatal("answered a name not in the list")
	}
	// Lists loaded later reach the router.
	g.r.SetLists(nil)
	if g.ask(t, "mail.ru", dnsmessage.TypeA) != nil {
		t.Fatal("answered without the list")
	}
}

func TestUpdateLists(t *testing.T) {
	body := []byte("list file body")
	sum := sha256.Sum256(body)
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits[r.URL.Path]++
		switch r.URL.Path {
		case "/geoip.dat":
			w.Write(body)
		case "/geoip.dat.sha256sum":
			w.Write([]byte(hex.EncodeToString(sum[:]) + "  geoip.dat\n"))
		case "/geosite.dat":
			w.Write([]byte("tampered"))
		case "/geosite.dat.sha256sum":
			w.Write([]byte(hex.EncodeToString(sum[:]) + "  geosite.dat\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := ListSources
	ListSources = []string{srv.URL + "/missing/", srv.URL + "/"}
	defer func() { ListSources = old }()
	dir := t.TempDir()
	changed, err := UpdateLists(context.Background(), dir, []string{GeoIPFile, GeoSiteFile}, true, ListClient{C: srv.Client()})
	if !slices.Equal(changed, []string{GeoIPFile}) || err == nil {
		t.Fatalf("changed %v, err %v", changed, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, GeoIPFile)); string(b) != string(body) {
		t.Fatal("file not saved")
	}
	if _, err := os.Stat(filepath.Join(dir, GeoSiteFile)); err == nil {
		t.Fatal("a file that failed its checksum was kept")
	}
	// The same checksum again: nothing is downloaded.
	n := hits["/geoip.dat"]
	changed, err = UpdateLists(context.Background(), dir, []string{GeoIPFile}, true, ListClient{C: srv.Client()})
	if len(changed) != 0 || err != nil || hits["/geoip.dat"] != n {
		t.Fatalf("again: %v %v %d", changed, err, hits["/geoip.dat"]-n)
	}
	// A fresh file is not even checked without force.
	sums := hits["/geoip.dat.sha256sum"]
	if changed, err = UpdateLists(context.Background(), dir, []string{GeoIPFile}, false, ListClient{C: srv.Client()}); len(changed) != 0 || err != nil || hits["/geoip.dat.sha256sum"] != sums {
		t.Fatalf("fresh: %v %v", changed, err)
	}
	// Errors name each way and source, shortly.
	_, err = UpdateLists(context.Background(), t.TempDir(), []string{GeoSiteFile}, false, ListClient{Via: "через VPN", C: srv.Client()})
	if err == nil || !strings.Contains(err.Error(), "через VPN, 127.0.0.1") || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("error: %v", err)
	}
	if fs := ListFiles(dir); len(fs) != 1 || fs[0].Size != int64(len(body)) {
		t.Fatalf("files %+v", fs)
	}
	if f := NeededFiles([]ListRule{{List: "geosite:a"}, {List: "geoip:b", Off: true}}); !slices.Equal(f, []string{GeoSiteFile}) {
		t.Fatalf("needed %v", f)
	}
}
