package split

import (
	"net/netip"
	"testing"
)

var testGames = []Game{
	{Name: "Steam", Rule: AppRule{Path: `C:\Steam\steam.exe`, Children: true, Route: Direct}},
	{Name: "Steam", Rule: AppRule{Path: `D:\Lib\steamapps\common`, Folder: true, Route: Direct}},
}

func TestGamesDirect(t *testing.T) {
	dst := netip.MustParseAddr("203.0.113.7")
	game := &Proc{Path: `D:\Lib\steamapps\common\Dota 2\dota2.exe`}
	child := &Proc{Path: `E:\Other\game.exe`, Parents: []string{`C:\Steam\steam.exe`}}
	other := &Proc{Path: `C:\Browser\browser.exe`}

	// Split tunneling off: only the games go direct.
	off := withGames(Rules{Games: true}, testGames)
	m := newMatcherRaw(off)
	for _, p := range []*Proc{game, child} {
		if d := m.decide(dst, "", p); d.Route != Direct {
			t.Fatalf("%s: %v", p.Path, d)
		}
	}
	if d := m.decide(dst, "", other); d.Route != VPN {
		t.Fatalf("other program: %v", d)
	}

	// A mode on: the games go direct, the user's own rule for one wins,
	// and a site sent through the VPN still goes through it.
	r := Rules{On: true, Default: VPN, Games: true,
		Apps:    []AppRule{{Path: `C:\Steam\steam.exe`, Route: VPN}},
		Domains: []DomainRule{{Domain: "blocked.example", Route: VPN}}}
	m = newMatcherRaw(withGames(r, testGames))
	if d := m.decide(dst, "", game); d.Route != Direct {
		t.Fatalf("game in a mode: %v", d)
	}
	if d := m.decide(dst, "", &Proc{Path: `C:\Steam\steam.exe`}); d.Route != VPN {
		t.Fatalf("the user's own rule lost: %v", d)
	}
	if d := m.decide(dst, "blocked.example", game); d.Route != VPN {
		t.Fatalf("site through the VPN from a game: %v", d)
	}
	// Off: nothing changes.
	if got := withGames(Rules{On: true}, testGames); len(got.Apps) != 0 {
		t.Fatal("games added while off")
	}
}

// newMatcherRaw builds a matcher from rules already expanded (without
// looking for games on this computer).
func newMatcherRaw(r Rules) *matcher {
	r.Games = false
	return newMatcher(r, nil, nil)
}

func TestPlanGames(t *testing.T) {
	if p := PlanApps(Rules{Games: true}); p.Mode != "disallow" || !p.Games {
		t.Fatalf("off: %+v", p)
	}
	if p := PlanApps(Rules{On: true, Default: VPN, Games: true, Domains: []DomainRule{{Domain: "x.example", Route: VPN}}}); !p.Games {
		t.Fatalf("with sites through the VPN: %+v", p)
	}
	if p := PlanApps(Rules{On: true, AppsOnly: true, Default: Direct, Games: true}); p.Mode != "allow" || p.Games {
		t.Fatalf("only chosen apps: %+v", p)
	}
}
