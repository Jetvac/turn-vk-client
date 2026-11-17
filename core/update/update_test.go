package update

import (
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"0.4.0", "0.3.1", true},
		{"0.3.1", "0.3.1", false},
		{"0.3.1", "0.4.0", false},
		{"0.3.10", "0.3.9", true},
		{"1.0.0", "0.99.99", true},
		{"0.3.1", "dev", true},
		{"0.3.1", "0.3.1-abc1234", false},
		{"0.3.2", "0.3.1-abc1234", true},
		{"v0.4.0", "0.3.1", true},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestParseSums(t *testing.T) {
	sums := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  TurnVK-v0.4.0.apk\n" +
		"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210  TurnVK-v0.4.0-windows-amd64.exe\n"
	got, err := parseSums(strings.NewReader(sums), "TurnVK-v0.4.0-windows-amd64.exe")
	if err != nil || !strings.HasPrefix(got, "fedcba") {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := parseSums(strings.NewReader(sums), "other"); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}
