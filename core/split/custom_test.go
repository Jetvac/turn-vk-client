package split

import "testing"

// Choosing "own rules" after a ready-made mode keeps that choice even
// though the mode's lists are still there.
func TestCustomModeSticks(t *testing.T) {
	for _, from := range []string{ModeBlocked, ModeRussia, ModeApps} {
		r := ApplyMode(DefaultRules(), from)
		if ModeOf(r) != from {
			t.Fatalf("%s: got %s", from, ModeOf(r))
		}
		c := ApplyMode(r, ModeCustom)
		if m := ModeOf(c); m != ModeCustom {
			t.Fatalf("%s -> custom: got %s", from, m)
		}
		if len(c.Lists) != len(r.Lists) || len(c.Domains) != len(r.Domains) {
			t.Fatalf("%s -> custom changed the rules", from)
		}
		if back := ApplyMode(c, from); ModeOf(back) != from {
			t.Fatalf("custom -> %s: got %s", from, ModeOf(back))
		}
	}
	// Turned off and on again: still own rules.
	c := ApplyMode(ApplyMode(DefaultRules(), ModeBlocked), ModeCustom)
	c.On = false
	if ModeOf(c) != ModeVPN {
		t.Fatal("off is not vpn")
	}
	c.On = true
	if ModeOf(c) != ModeCustom {
		t.Fatal("on again lost own rules")
	}
}
