package split

// Lists of addresses and sites kept by others: the countries' address
// blocks (geoip) and categories of sites (geosite), in the v2ray .dat
// format that xray, v2rayN and sing-box use. The files come from
// runetfreedom/russia-v2ray-rules-dat: every country, the v2fly site
// categories (youtube, discord...) and Russian lists (sites blocked in
// Russia, sites that open only from inside).

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ListRule routes everything in a list: "geoip:ru" (addresses of a country
// or a service), "geosite:youtube" (sites of a category).
type ListRule struct {
	List  string `json:"list"`
	Route Route  `json:"route"`
	Off   bool   `json:"off,omitempty"`
}

const (
	geoipPrefix   = "geoip:"
	geositePrefix = "geosite:"
)

// NormalizeList checks a list's name ("geoip:RU" -> "geoip:ru").
func NormalizeList(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	kind, code, ok := strings.Cut(s, ":")
	if !ok || (kind+":" != geoipPrefix && kind+":" != geositePrefix) {
		return "", errors.New("список должен начинаться с geoip: или geosite:")
	}
	code = strings.TrimSpace(code)
	if code == "" || len(code) > 64 {
		return "", errors.New("пустое имя списка")
	}
	for _, c := range code {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '!' || c == '@' || c == '.') {
			return "", fmt.Errorf("неверное имя списка: %s", code)
		}
	}
	return kind + ":" + code, nil
}

// IPSet is a set of IPv4 ranges, sorted and merged.
type IPSet struct{ r []ipRange }

type ipRange struct{ lo, hi uint32 }

func v4(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func newIPSet(r []ipRange) *IPSet {
	sort.Slice(r, func(i, j int) bool { return r[i].lo < r[j].lo })
	out := r[:0]
	for _, x := range r {
		if n := len(out); n > 0 && x.lo <= out[n-1].hi+1 && out[n-1].hi != ^uint32(0) {
			if x.hi > out[n-1].hi {
				out[n-1].hi = x.hi
			}
			continue
		}
		out = append(out, x)
	}
	return &IPSet{r: out}
}

// Contains reports whether a (IPv4) is in the set.
func (s *IPSet) Contains(a netip.Addr) bool {
	if s == nil || !a.Is4() {
		return false
	}
	x := v4(a)
	i := sort.Search(len(s.r), func(i int) bool { return s.r[i].hi >= x })
	return i < len(s.r) && s.r[i].lo <= x
}

// Len is the number of ranges.
func (s *IPSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.r)
}

// SiteSet is a category of sites.
type SiteSet struct {
	full     map[string]struct{} // the name only
	domain   map[string]struct{} // the name and its subdomains
	keywords []string            // names containing the word
	regexps  []*regexp.Regexp
}

// Match reports whether name (ASCII, any case, maybe with the final dot)
// is in the set.
func (s *SiteSet) Match(name string) bool {
	if s == nil || name == "" {
		return false
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if _, ok := s.full[name]; ok {
		return true
	}
	for n := name; ; {
		if _, ok := s.domain[n]; ok {
			return true
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			break
		}
		n = n[i+1:]
	}
	for _, k := range s.keywords {
		if strings.Contains(name, k) {
			return true
		}
	}
	for _, re := range s.regexps {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// Len is the number of entries.
func (s *SiteSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.full) + len(s.domain) + len(s.keywords) + len(s.regexps)
}

// Lists holds the loaded lists, by name ("geoip:ru").
type Lists struct {
	IP   map[string]*IPSet
	Site map[string]*SiteSet
}

// Has reports whether a list was found in the files.
func (l *Lists) Has(name string) bool {
	if l == nil {
		return false
	}
	return l.IP[name] != nil || l.Site[name] != nil
}

// GeoIPFile and GeoSiteFile are the names of the files in the lists folder.
const (
	GeoIPFile   = "geoip.dat"
	GeoSiteFile = "geosite.dat"
)

// LoadLists reads the lists the rules name from the folder dir. Lists
// missing from the files (or files not yet downloaded) are left out.
func LoadLists(dir string, rules []ListRule) (*Lists, error) {
	ip, site := map[string]bool{}, map[string]bool{}
	for _, r := range rules {
		if r.Off {
			continue
		}
		if c, ok := strings.CutPrefix(r.List, geoipPrefix); ok {
			ip[c] = true
		} else if c, ok := strings.CutPrefix(r.List, geositePrefix); ok {
			site[c] = true
		}
	}
	l := &Lists{IP: map[string]*IPSet{}, Site: map[string]*SiteSet{}}
	var errs []error
	if len(ip) > 0 {
		if err := readGeoIP(filepath.Join(dir, GeoIPFile), ip, l.IP); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", GeoIPFile, err))
		}
	}
	if len(site) > 0 {
		if err := readGeoSite(filepath.Join(dir, GeoSiteFile), site, l.Site); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", GeoSiteFile, err))
		}
	}
	return l, errors.Join(errs...)
}

// ListNames returns the names of all lists in a file ("ru", "youtube"...).
func ListNames(path string) ([]string, error) {
	var out []string
	err := scanDat(path, func(code string) bool {
		out = append(out, code)
		return false
	}, nil)
	sort.Strings(out)
	return out, err
}

// --- the .dat files: protobuf, read by hand ---
//
//	GeoIPList   { repeated GeoIP   entry = 1 }
//	GeoIP       { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3 }
//	CIDR        { bytes ip = 1; uint32 prefix = 2 }
//	GeoSiteList { repeated GeoSite entry = 1 }
//	GeoSite     { string country_code = 1; repeated Domain domain = 2 }
//	Domain      { Type type = 1; string value = 2; ... }  Plain=0 Regex=1 Domain=2 Full=3

var errBad = errors.New("файл списков повреждён")

func uvarint(b []byte) (uint64, int) {
	var x uint64
	for i := 0; i < len(b) && i < 10; i++ {
		x |= uint64(b[i]&0x7f) << (7 * i)
		if b[i] < 0x80 {
			return x, i + 1
		}
	}
	return 0, 0
}

// fields calls f for every field of a message: varints get v, length-
// delimited fields get data.
func fields(b []byte, f func(num int, v uint64, data []byte) error) error {
	for len(b) > 0 {
		tag, n := uvarint(b)
		if n == 0 {
			return errBad
		}
		b = b[n:]
		num := int(tag >> 3)
		switch tag & 7 {
		case 0:
			v, n := uvarint(b)
			if n == 0 {
				return errBad
			}
			b = b[n:]
			if err := f(num, v, nil); err != nil {
				return err
			}
		case 2:
			l, n := uvarint(b)
			if n == 0 || l > uint64(len(b)-n) {
				return errBad
			}
			data := b[n : n+int(l)]
			b = b[n+int(l):]
			if err := f(num, 0, data); err != nil {
				return err
			}
		case 1:
			if len(b) < 8 {
				return errBad
			}
			b = b[8:]
		case 5:
			if len(b) < 4 {
				return errBad
			}
			b = b[4:]
		default:
			return errBad
		}
	}
	return nil
}

var errStop = errors.New("stop")

// scanDat reads a .dat file list by list without holding it all (the
// site file is near 90 MB): want sees each list's name, and only the
// lists it wants are read whole and given to f.
func scanDat(path string, want func(code string) bool, f func(code string, entry []byte) error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	br := bufio.NewReaderSize(file, 64<<10)
	for {
		tag, err := binary.ReadUvarint(br)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errBad
		}
		switch tag & 7 {
		case 0:
			if _, err := binary.ReadUvarint(br); err != nil {
				return errBad
			}
			continue
		case 2:
		default:
			return errBad
		}
		l, err := binary.ReadUvarint(br)
		if err != nil || l > 1<<30 {
			return errBad
		}
		if tag>>3 != 1 {
			if _, err := br.Discard(int(l)); err != nil {
				return errBad
			}
			continue
		}
		// The list's name is its first field: peek at it.
		head, _ := br.Peek(int(min(l, 256)))
		var code string
		fields(head, func(num int, _ uint64, d []byte) error {
			if num == 1 && d != nil {
				code = strings.ToLower(string(d))
			}
			return errStop
		})
		if code == "" || !want(code) || f == nil {
			if _, err := br.Discard(int(l)); err != nil {
				return errBad
			}
			continue
		}
		entry := make([]byte, l)
		if _, err := io.ReadFull(br, entry); err != nil {
			return errBad
		}
		if err := f(code, entry); err != nil {
			return err
		}
	}
}

func readGeoIP(path string, want map[string]bool, out map[string]*IPSet) error {
	return scanDat(path, func(c string) bool { return want[c] }, func(code string, entry []byte) error {
		if !want[code] {
			return nil
		}
		var rs []ipRange
		reverse := false
		err := fields(entry, func(num int, v uint64, d []byte) error {
			switch {
			case num == 3:
				reverse = v != 0
			case num == 2 && d != nil:
				var ip []byte
				var bits uint64
				if err := fields(d, func(num int, v uint64, d []byte) error {
					if num == 1 {
						ip = d
					} else if num == 2 {
						bits = v
					}
					return nil
				}); err != nil {
					return err
				}
				if len(ip) != 4 || bits > 32 { // IPv6: the router handles IPv4 only
					return nil
				}
				lo := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
				mask := uint32(0)
				if bits < 32 {
					mask = ^uint32(0) >> bits
				}
				rs = append(rs, ipRange{lo &^ mask, lo | mask})
			}
			return nil
		})
		if err != nil {
			return err
		}
		if reverse { // "everything but": rare, and not in these files
			return nil
		}
		out[geoipPrefix+code] = newIPSet(rs)
		return nil
	})
}

func readGeoSite(path string, want map[string]bool, out map[string]*SiteSet) error {
	return scanDat(path, func(c string) bool { return want[c] }, func(code string, entry []byte) error {
		if !want[code] {
			return nil
		}
		s := &SiteSet{full: map[string]struct{}{}, domain: map[string]struct{}{}}
		err := fields(entry, func(num int, _ uint64, d []byte) error {
			if num != 2 || d == nil {
				return nil
			}
			var typ uint64
			var val string
			if err := fields(d, func(num int, v uint64, d []byte) error {
				if num == 1 {
					typ = v
				} else if num == 2 && d != nil {
					val = strings.ToLower(string(d))
				}
				return nil
			}); err != nil {
				return err
			}
			if val == "" {
				return nil
			}
			switch typ {
			case 0:
				s.keywords = append(s.keywords, val)
			case 1:
				if re, err := regexp.Compile(val); err == nil {
					s.regexps = append(s.regexps, re)
				}
			case 2:
				s.domain[strings.Trim(val, ".")] = struct{}{}
			case 3:
				s.full[strings.Trim(val, ".")] = struct{}{}
			}
			return nil
		})
		if err != nil {
			return err
		}
		out[geositePrefix+code] = s
		return nil
	})
}
