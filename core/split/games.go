package split

import (
	"sync"
	"time"
)

// "Games direct" (Rules.Games): games and their launchers go around the
// VPN, whatever the mode: most games are not blocked, and direct they get
// the lowest ping (no VK relay, no server on the way). On Windows the
// rules cover the launchers found on the computer and the games they
// start (Children), and the folders games are installed in (GameApps);
// on Android the system keeps game apps out of the tunnel (AppPlan.Games).
// Sites the rules send through the VPN still go through it, and a site
// that does not open direct is retried through it (unless NoRetry).

// Game is a launcher (or a folder of games) found on the computer.
type Game struct {
	Name string // shown to people: "Steam"
	Rule AppRule
}

var gamesCache struct {
	mu sync.Mutex
	at time.Time
	gs []Game
}

// FindGames lists the launchers and game folders on this computer
// (Windows; none elsewhere). Looked up at most once a minute.
func FindGames() []Game {
	gamesCache.mu.Lock()
	defer gamesCache.mu.Unlock()
	if time.Since(gamesCache.at) > time.Minute {
		gamesCache.gs, gamesCache.at = findGames(), time.Now()
	}
	return gamesCache.gs
}

// GameNames: the launchers found, each once, in order.
func GameNames() []string {
	var out []string
	seen := map[string]bool{}
	for _, g := range FindGames() {
		if !seen[g.Name] {
			seen[g.Name] = true
			out = append(out, g.Name)
		}
	}
	return out
}

// withGames adds the rules "games direct" stands for. Split tunneling
// itself off: everything else goes through the VPN.
func withGames(r Rules, games []Game) Rules {
	if !r.Games {
		return r
	}
	if !r.On {
		r = Rules{On: true, Default: VPN, Games: true}
	}
	if r.AppsOnly {
		return r // programs not chosen go direct anyway
	}
	// The user's own rules for the same programs and folders win.
	own := map[string]bool{}
	for _, a := range r.Apps {
		own[normPath(a.Path)] = true
	}
	apps := append([]AppRule(nil), r.Apps...)
	for _, g := range games {
		if !own[normPath(g.Rule.Path)] {
			apps = append(apps, g.Rule)
		}
	}
	r.Apps = apps
	return r
}
