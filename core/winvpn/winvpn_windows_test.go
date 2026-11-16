//go:build windows

package winvpn

import (
	"testing"

	"golang.org/x/sys/windows"
)

// The computer running the tests has a network: its default route is found.
func TestDefaultInterface(t *testing.T) {
	i4 := defaultInterface(windows.AF_INET, 0)
	t.Logf("IPv4 interface %d, IPv6 interface %d", i4, defaultInterface(windows.AF_INET6, 0))
	if i4 == 0 {
		t.Skip("no IPv4 default route here")
	}
}

// Whatever runs on the test machine: OtherVPN must not panic and must not
// report TurnVK itself.
func TestOtherVPN(t *testing.T) {
	name := OtherVPN()
	t.Logf("other VPN: %q", name)
	if name == AdapterName {
		t.Fatal("reported our own adapter")
	}
}
