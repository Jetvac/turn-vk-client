//go:build windows

package winvpn

import "testing"

func TestParseSSID(t *testing.T) {
	out := []byte("\r\nВ системе есть 2 интерфейса:\r\n\r\n    Имя                    : Ethernet 2\r\n    SSID                   : Other\r\n\r\n    Имя                    : Беспроводная сеть\r\n    Описание               : Intel Wi-Fi 6\r\n    Состояние              : подключено\r\n    SSID                   : Home Net\r\n    BSSID                  : aa:bb:cc:dd:ee:ff\r\n")
	if s := parseSSID(out, "Беспроводная сеть"); s != "Home Net" {
		t.Fatalf("got %q", s)
	}
	if s := parseSSID(out, "nope"); s != "" {
		t.Fatalf("two adapters, none named: %q", s)
	}
}
