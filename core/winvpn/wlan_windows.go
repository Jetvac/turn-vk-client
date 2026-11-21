//go:build windows

package winvpn

import (
	"bytes"
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Link is the physical network under the tunnel, for the statistics: its
// kind ("wifi", "wired", "mobile", "other"; "none" without one) and, for
// Wi-Fi, the link as Windows sees it. Never the network's name.
type Link struct {
	Kind    string
	Quality int // Wi-Fi signal quality, %
	RSSI    int // dBm
	RxMbps  int // Wi-Fi receive rate
	MHz     int // channel frequency
}

// Link describes the network TurnVK's routes go through now.
func (v *VPN) Link() Link {
	idx := v.if4.Load()
	if idx == 0 {
		return Link{Kind: "none"}
	}
	luid, err := winipcfg.LUIDFromIndex(idx)
	if err != nil {
		return Link{Kind: "other"}
	}
	row, err := luid.Interface()
	if err != nil {
		return Link{Kind: "other"}
	}
	switch row.Type {
	case winipcfg.IfTypeIEEE80211:
		l := Link{Kind: "wifi"}
		if g, err := luid.GUID(); err == nil {
			wifiLink(g, &l)
		}
		return l
	case winipcfg.IfTypeEthernetCSMACD:
		return Link{Kind: "wired"}
	case winipcfg.IfTypeWwanpp, winipcfg.IfTypeWwanpp2:
		return Link{Kind: "mobile"}
	}
	return Link{Kind: "other"}
}

var (
	wlanapi                = windows.NewLazySystemDLL("wlanapi.dll")
	procWlanOpenHandle     = wlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle    = wlanapi.NewProc("WlanCloseHandle")
	procWlanQueryInterface = wlanapi.NewProc("WlanQueryInterface")
	procWlanFreeMemory     = wlanapi.NewProc("WlanFreeMemory")
)

// WLAN_INTF_OPCODE values.
const (
	wlanCurrentConnection = 7
	wlanChannelNumber     = 8
	wlanRSSI              = 0x10000102
)

// wifiLink fills in the link of the Wi-Fi adapter guid from the Native
// Wi-Fi API (what "netsh wlan show interfaces" shows, without a process).
func wifiLink(guid *windows.GUID, l *Link) {
	if procWlanOpenHandle.Find() != nil {
		return // no WLAN service (Windows Server)
	}
	var ver uint32
	var h windows.Handle
	if r, _, _ := procWlanOpenHandle.Call(2, 0, uintptr(unsafe.Pointer(&ver)), uintptr(unsafe.Pointer(&h))); r != 0 {
		return
	}
	defer procWlanCloseHandle.Call(uintptr(h), 0)
	query := func(op uint32) []byte {
		var size uint32
		var data *byte
		r, _, _ := procWlanQueryInterface.Call(uintptr(h), uintptr(unsafe.Pointer(guid)), uintptr(op), 0,
			uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), 0)
		if r != 0 || data == nil {
			return nil
		}
		defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(data)))
		return bytes.Clone(unsafe.Slice(data, size))
	}
	parseConnection(query(wlanCurrentConnection), l)
	if b := query(wlanRSSI); len(b) >= 4 {
		if r := int(int32(binary.LittleEndian.Uint32(b))); r < 0 && r > -128 {
			l.RSSI = r
		}
	}
	if b := query(wlanChannelNumber); len(b) >= 4 {
		l.MHz = channelMHz(int(binary.LittleEndian.Uint32(b)))
	}
}

// parseConnection reads WLAN_CONNECTION_ATTRIBUTES: the state (1:
// connected), then the association's signal quality (%) and receive rate
// (kbit/s) at their offsets in the structure.
func parseConnection(b []byte, l *Link) {
	const quality, rx = 576, 580
	if len(b) < rx+4 || binary.LittleEndian.Uint32(b) != 1 {
		return
	}
	l.Quality = int(binary.LittleEndian.Uint32(b[quality:]))
	l.RxMbps = int(binary.LittleEndian.Uint32(b[rx:]) / 1000)
}

// channelMHz: a Wi-Fi channel's frequency (2.4 or 5 GHz band; 6 GHz
// channels reuse the numbers and read as 5 GHz).
func channelMHz(ch int) int {
	switch {
	case ch >= 1 && ch <= 13:
		return 2407 + 5*ch
	case ch == 14:
		return 2484
	case ch >= 32 && ch <= 177:
		return 5000 + 5*ch
	}
	return 0
}
