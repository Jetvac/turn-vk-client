package split

import (
	"strings"
	"sync"
	"time"
)

// Anti-cheat services (Easy Anti-Cheat, BattlEye, Riot Vanguard, FACEIT)
// and Epic Online Services run as Windows services, not as programs the
// game or its launcher starts, so no game rule covers them: with games
// direct they went through the VPN while the game went direct. The game's
// server then saw the player at one address and the anti-cheat's at
// another, and the match did not start (Fortnite: "searching for a
// game", the party stuck at "connecting to server"). So an anti-cheat
// service takes the route of the game that ran last, whatever sent that
// game where it goes (a game rule, the user's own rule, or appwatch.go).
// A rule of the user's own for the service itself still wins.
const (
	// gameRecent: a game's connection this recent decides an anti-cheat's
	// route; with none, the anti-cheat's own decision stands.
	gameRecent   = 10 * time.Minute
	whyAntiCheat = "античит следует за игрой "
)

// antiCheatDirs: the folders of the anti-cheat services installed here
// (normPath form), found once.
var antiCheatDirs = sync.OnceValue(findAntiCheat)

// isAntiCheat: path is in an anti-cheat service's folder.
func isAntiCheat(path string) bool {
	n := normPath(path)
	for _, d := range antiCheatDirs() {
		if strings.HasPrefix(n, d+`\`) {
			return true
		}
	}
	return false
}

// gameSeen: the route of the game that ran last.
type gameSeen struct {
	name  string
	route Route
	at    int64 // unix ns
}

// isGameRule: a's rule covers a game: a folder of games, or a program a
// launcher started (parent).
func isGameRule(a *AppRule, parent string) bool {
	return a != nil && (a.Folder || parent != "")
}

// noteGame records the route a game's connection took.
func (r *Router) noteGame(path string, route Route, now int64) {
	r.gmu.Lock()
	r.game = gameSeen{name: baseName(path), route: route, at: now}
	r.gmu.Unlock()
}

// lastGame returns the route of the game that ran last, if recently.
func (r *Router) lastGame(now int64) (gameSeen, bool) {
	r.gmu.Lock()
	defer r.gmu.Unlock()
	g := r.game
	return g, g.at != 0 && now-g.at < int64(gameRecent)
}
