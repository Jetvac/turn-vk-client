package split

import (
	"errors"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

// DomainRule routes a site and all its subdomains: "example.com" covers
// www.example.com too, "su" covers every .su site.
type DomainRule struct {
	// Domain as the user wrote it, normalized (lower case, Unicode for
	// international names: "рф", not "xn--p1ai").
	Domain string `json:"domain"`
	Route  Route  `json:"route"`
	Off    bool   `json:"off,omitempty"`
}

// NormalizeDomain turns what the user typed — a domain, "*.example.com",
// ".su" or a whole URL — into the form rules keep. Only the site's name can
// be matched: HTTPS hides the rest of a URL.
func NormalizeDomain(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			s = u.Hostname()
		}
	} else if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, ok := strings.Cut(s, ":"); ok {
		s = h
	}
	s = strings.TrimPrefix(s, "*")
	s = strings.Trim(s, ".")
	// "www.example.com" from a browser's address bar means the site:
	// example.com covers www too.
	if strings.HasPrefix(s, "www.") && strings.Count(s, ".") >= 2 {
		s = s[4:]
	}
	if s == "" {
		return "", errors.New("пустое имя")
	}
	a, err := toASCII(s)
	if err != nil {
		return "", err
	}
	u, err := idna.ToUnicode(a)
	if err != nil {
		return "", err
	}
	return u, nil
}

// toASCII is the form names have in DNS (punycode), checked label by label.
func toASCII(s string) (string, error) {
	a, err := idna.Lookup.ToASCII(s)
	if err != nil {
		// Underscores and the like: let plain ASCII names through.
		a = s
	}
	if len(a) > 253 {
		return "", errors.New("слишком длинное имя")
	}
	for _, l := range strings.Split(a, ".") {
		if l == "" || len(l) > 63 {
			return "", errors.New("неверное имя: " + s)
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", errors.New("неверное имя: " + s)
			}
		}
	}
	return a, nil
}

// domains matches names against the rules: the longest suffix on a label
// boundary wins ("mail.example.com" beats "example.com" beats "com").
type domains map[string]*DomainRule

func newDomains(rules []DomainRule) domains {
	d := domains{}
	for i := range rules {
		r := &rules[i]
		if r.Off {
			continue
		}
		if a, err := toASCII(r.Domain); err == nil {
			d[a] = r
		}
	}
	return d
}

// match finds the rule for a name from DNS (ASCII, any case, maybe with
// the final dot).
func (d domains) match(name string) *DomainRule {
	if len(d) == 0 || name == "" {
		return nil
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for {
		if r := d[name]; r != nil {
			return r
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return nil
		}
		name = name[i+1:]
	}
}

// hasDirect: some rule sends sites direct (they get placeholder addresses).
func (d domains) hasDirect() bool {
	for _, r := range d {
		if r.Route == Direct {
			return true
		}
	}
	return false
}
