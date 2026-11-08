package engine

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// WGConfig is the WireGuard config the server sends in answer to GETCONF.
type WGConfig struct {
	PrivateKey string // base64
	Address    netip.Prefix
	DNS        []netip.Addr
	MTU        int
	PublicKey  string // server, base64
	AllowedIPs []netip.Prefix
	Keepalive  int
}

// ParseWGConfig reads the INI-style config.
func ParseWGConfig(s string) (*WGConfig, error) {
	c := &WGConfig{MTU: 1280, Keepalive: 25}
	section := ""
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch section + "." + k {
		case "interface.privatekey":
			c.PrivateKey = v
		case "interface.address":
			for _, a := range strings.Split(v, ",") {
				p, err := netip.ParsePrefix(strings.TrimSpace(a))
				if err == nil && p.Addr().Is4() && !c.Address.IsValid() {
					c.Address = p
				}
			}
		case "interface.dns":
			for _, a := range strings.Split(v, ",") {
				if ip, err := netip.ParseAddr(strings.TrimSpace(a)); err == nil {
					c.DNS = append(c.DNS, ip)
				}
			}
		case "interface.mtu":
			if m, err := strconv.Atoi(v); err == nil && m >= 576 && m <= 1500 {
				c.MTU = m
			}
		case "peer.publickey":
			c.PublicKey = v
		case "peer.allowedips":
			for _, a := range strings.Split(v, ",") {
				if p, err := netip.ParsePrefix(strings.TrimSpace(a)); err == nil {
					c.AllowedIPs = append(c.AllowedIPs, p)
				}
			}
		case "peer.persistentkeepalive":
			if n, err := strconv.Atoi(v); err == nil {
				c.Keepalive = n
			}
		}
	}
	switch {
	case c.PrivateKey == "" || c.PublicKey == "":
		return nil, errors.New("the server's WireGuard config has no keys")
	case !c.Address.IsValid():
		return nil, errors.New("the server's WireGuard config has no IPv4 address")
	}
	if len(c.AllowedIPs) == 0 {
		c.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	}
	return c, nil
}

// uapi returns the config in wireguard-go's IPC format.
func (c *WGConfig) uapi() (string, error) {
	priv, err := b64hex(c.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	pub, err := b64hex(c.PublicKey)
	if err != nil {
		return "", fmt.Errorf("server public key: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nreplace_peers=true\npublic_key=%s\nendpoint=wdtt:0\npersistent_keepalive_interval=%d\nreplace_allowed_ips=true\n", priv, pub, c.Keepalive)
	for _, p := range c.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", p)
	}
	return b.String(), nil
}

func b64hex(s string) (string, error) {
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(k) != 32 {
		return "", errors.New("not a 32-byte key")
	}
	return hex.EncodeToString(k), nil
}
