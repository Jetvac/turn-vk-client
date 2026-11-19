//go:build windows

package split

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// findGames looks for the usual launchers and the folders their games are
// installed in. A launcher's rule covers the programs it starts (the
// games, wherever they are installed).
func findGames() []Game {
	var out []Game
	seen := map[string]bool{}
	add := func(name, path string, folder bool) {
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		st, err := os.Stat(path)
		if err != nil || st.IsDir() != folder || seen[strings.ToLower(path)] {
			return
		}
		seen[strings.ToLower(path)] = true
		out = append(out, Game{Name: name, Rule: AppRule{Path: path, Folder: folder, Children: !folder, Route: Direct}})
	}
	pf, pf86, pd := os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramData")

	// Steam: its folder and every library's games.
	if k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Valve\Steam`, registry.QUERY_VALUE); err == nil {
		if p, _, err := k.GetStringValue("SteamPath"); err == nil && p != "" {
			p = filepath.Clean(p)
			add("Steam", filepath.Join(p, "steam.exe"), false)
			add("Steam", filepath.Join(p, "steamapps", "common"), true)
			for _, lib := range steamLibraries(filepath.Join(p, "steamapps", "libraryfolders.vdf")) {
				add("Steam", filepath.Join(lib, "steamapps", "common"), true)
			}
		}
		k.Close()
	}

	// Epic Games: the launcher and each installed game.
	for _, root := range []string{pf86, pf} {
		for _, sub := range []string{"Win64", "Win32"} {
			add("Epic Games", filepath.Join(root, `Epic Games\Launcher\Portal\Binaries`, sub, "EpicGamesLauncher.exe"), false)
		}
	}
	if items, _ := filepath.Glob(filepath.Join(pd, `Epic\EpicGamesLauncher\Data\Manifests\*.item`)); len(items) > 0 {
		for _, f := range items {
			var m struct{ InstallLocation string }
			if b, err := os.ReadFile(f); err == nil && json.Unmarshal(b, &m) == nil {
				add("Epic Games", m.InstallLocation, true)
			}
		}
	}

	// Riot Games (League of Legends, Valorant): everything under its root.
	var riot struct {
		Default string `json:"rc_default"`
	}
	if b, err := os.ReadFile(filepath.Join(pd, `Riot Games\RiotClientInstalls.json`)); err == nil && json.Unmarshal(b, &riot) == nil && riot.Default != "" {
		add("Riot Games", filepath.Dir(filepath.Dir(filepath.Clean(riot.Default))), true)
	}
	add("Riot Games", `C:\Riot Games`, true)

	// Battle.net, EA app, Ubisoft Connect, GOG Galaxy.
	add("Battle.net", filepath.Join(pf86, `Battle.net\Battle.net.exe`), false)
	add("Battle.net", filepath.Join(pf86, `Battle.net\Battle.net Launcher.exe`), false)
	add("EA app", filepath.Join(pf, `Electronic Arts\EA Desktop\EA Desktop\EADesktop.exe`), false)
	add("EA app", filepath.Join(pf, "EA Games"), true)
	add("Ubisoft Connect", filepath.Join(pf86, `Ubisoft\Ubisoft Game Launcher\upc.exe`), false)
	add("Ubisoft Connect", filepath.Join(pf86, `Ubisoft\Ubisoft Game Launcher\games`), true)
	add("GOG Galaxy", filepath.Join(pf86, `GOG Galaxy\GalaxyClient.exe`), false)
	add("GOG Galaxy", filepath.Join(pf86, `GOG Galaxy\Games`), true)
	return out
}

var vdfPath = regexp.MustCompile(`"path"\s+"([^"]+)"`)

// steamLibraries reads the library folders from Steam's libraryfolders.vdf.
func steamLibraries(file string) []string {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range vdfPath.FindAllStringSubmatch(string(b), -1) {
		out = append(out, strings.ReplaceAll(m[1], `\`, `\`))
	}
	return out
}
