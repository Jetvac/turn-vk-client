// Package link parses connection links of a WDTT server:
//
//	wdtt://HOST:DTLS_PORT:WG_PORT:LOCAL_PORT:PASSWORD:VK_CALLS
//
// VK_CALLS is one or more VK call links or their last path segment (the
// "hash"), separated by commas. The WireGuard and local ports are kept for
// compatibility with the original client; this client does not use them.
package link

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Link is a parsed wdtt:// link.
type Link struct {
	Host      string
	DTLSPort  int
	WGPort    int
	LocalPort int
	Password  string
	Hashes    []string
	// ServerKey is the server's WireGuard public key (32 bytes), from a
	// "?pk=" suffix that TurnVK links carry. With it the client speaks the
	// direct protocol and refuses any other server key.
	ServerKey []byte
}

// Peer is the server address the client talks to through TURN.
func (l Link) Peer() string { return net.JoinHostPort(l.Host, strconv.Itoa(l.DTLSPort)) }

// String formats the link back.
func (l Link) String() string {
	s := fmt.Sprintf("wdtt://%s:%d:%d:%d:%s:%s", l.Host, l.DTLSPort, l.WGPort, l.LocalPort, l.Password, strings.Join(l.Hashes, ","))
	if len(l.ServerKey) == 32 {
		s += "?pk=" + base64.RawURLEncoding.EncodeToString(l.ServerKey)
	}
	return s
}

var pkParam = regexp.MustCompile(`[?&]pk=([A-Za-z0-9_\-+/]{43}=?)`)

// cutServerKey removes the "?pk=" parameter from the call list.
func cutServerKey(s string) (string, []byte, error) {
	m := pkParam.FindStringSubmatchIndex(s)
	if m == nil {
		return s, nil, nil
	}
	enc := strings.TrimRight(s[m[2]:m[3]], "=")
	enc = strings.NewReplacer("+", "-", "/", "_").Replace(enc)
	k, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil || len(k) != 32 {
		return s, nil, errors.New("bad server key (pk) in the link")
	}
	return s[:m[0]] + s[m[1]:], k, nil
}

// Parse reads a wdtt:// link. The password must not contain ":"; everything
// after the fifth ":" is the list of VK calls (call links contain ":").
func Parse(raw string) (Link, error) {
	raw = strings.TrimSpace(raw)
	rest, ok := cutPrefixFold(raw, "wdtt://")
	if !ok {
		return Link{}, errors.New("not a wdtt:// link")
	}
	parts := strings.SplitN(rest, ":", 6)
	if len(parts) < 6 {
		return Link{}, errors.New("wdtt:// link has too few fields")
	}
	l := Link{Host: strings.TrimSpace(parts[0]), Password: strings.TrimSpace(parts[4])}
	var err error
	if l.DTLSPort, err = port(parts[1]); err != nil {
		return Link{}, fmt.Errorf("DTLS port: %w", err)
	}
	if l.WGPort, err = port(parts[2]); err != nil {
		l.WGPort = 0
	}
	if l.LocalPort, err = port(parts[3]); err != nil {
		l.LocalPort = 9000
	}
	calls, key, err := cutServerKey(parts[5])
	if err != nil {
		return Link{}, err
	}
	l.ServerKey = key
	l.Hashes = ParseHashes(calls)
	switch {
	case l.Host == "":
		return Link{}, errors.New("wdtt:// link has no server address")
	case l.Password == "":
		return Link{}, errors.New("wdtt:// link has no password")
	case len(l.Hashes) == 0:
		return Link{}, errors.New("wdtt:// link has no VK call")
	}
	return l, nil
}

func port(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return p, nil
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return s, false
	}
	return s[len(prefix):], true
}

// ParseHashes splits a list of VK calls (links or hashes, separated by
// commas, semicolons or whitespace) into unique call hashes.
func ParseHashes(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
	}) {
		if h := NormalizeHash(f); h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

// NormalizeHash turns "https://vk.com/call/join/HASH?x" or "HASH" into HASH.
func NormalizeHash(s string) string {
	s = strings.Trim(strings.TrimSpace(s), "<>\"'")
	lower := strings.ToLower(s)
	if i := strings.Index(lower, "/call/join/"); i >= 0 {
		s = s[i+len("/call/join/"):]
	} else if strings.Contains(lower, "://") {
		return ""
	}
	if i := strings.IndexAny(s, "?#/"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
