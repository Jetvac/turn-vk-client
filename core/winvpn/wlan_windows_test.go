//go:build windows

package winvpn

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/windows"
)

func TestParseConnection(t *testing.T) {
	b := make([]byte, 600)
	binary.LittleEndian.PutUint32(b, 1)
	binary.LittleEndian.PutUint32(b[576:], 78)
	binary.LittleEndian.PutUint32(b[580:], 866700)
	var l Link
	parseConnection(b, &l)
	if l.Quality != 78 || l.RxMbps != 866 {
		t.Fatalf("%+v", l)
	}
	binary.LittleEndian.PutUint32(b, 4) // disconnected
	l = Link{}
	if parseConnection(b, &l); l.Quality != 0 {
		t.Fatalf("%+v", l)
	}
	if channelMHz(6) != 2437 || channelMHz(36) != 5180 || channelMHz(0) != 0 {
		t.Fatal("channels")
	}
}

// What this computer's network reads as (no check: it depends on the
// machine).
func TestLinkHere(t *testing.T) {
	v := &VPN{}
	v.if4.Store(defaultInterface(windows.AF_INET, 0))
	t.Logf("%+v", v.Link())
}
