//go:build windows

package winvpn

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Network tells the kind of the physical network ("wifi", "wired",
// "mobile", "" when unknown) and, for Wi-Fi, its name (SSID).
func (v *VPN) Network() (kind, wifiName string) {
	idx := v.if4.Load()
	if idx == 0 {
		return "", ""
	}
	luid, err := winipcfg.LUIDFromIndex(idx)
	if err != nil {
		return "", ""
	}
	row, err := luid.Interface()
	if err != nil {
		return "", ""
	}
	switch row.Type {
	case winipcfg.IfTypeIEEE80211:
		return "wifi", wifiSSID(row.Alias())
	case winipcfg.IfTypeEthernetCSMACD:
		return "wired", ""
	case winipcfg.IfTypeWwanpp, winipcfg.IfTypeWwanpp2:
		return "mobile", ""
	}
	return "", ""
}

// wifiSSID asks Windows for the name of the Wi-Fi network the adapter
// (by its name) is connected to.
func wifiSSID(adapter string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "netsh", "wlan", "show", "interfaces")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return parseSSID(out, adapter)
}

// parseSSID reads "netsh wlan show interfaces": a block of "Key : value"
// lines per adapter, blocks apart by empty lines. The keys are translated,
// except "SSID"; the block is found by the adapter's name among the values.
func parseSSID(out []byte, adapter string) string {
	var first string
	ssids, cur := 0, false
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			cur = false
			continue
		}
		k, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, val = strings.TrimSpace(k), strings.TrimSpace(val)
		if adapter != "" && val == adapter {
			cur = true
		}
		if k == "SSID" {
			if cur {
				return val
			}
			ssids++
			if first == "" {
				first = val
			}
		}
	}
	if ssids == 1 {
		return first
	}
	return ""
}
