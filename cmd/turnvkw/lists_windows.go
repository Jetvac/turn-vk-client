package main

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Jetvac/turn-vk-client/core/engine"
	"github.com/Jetvac/turn-vk-client/core/split"
)

// Lists of countries and sites (geoip/geosite) for split tunneling. They
// are downloaded only through the tunnel (TurnVK's own connections go
// through the VPN), right after connecting and twice a day while connected.

const listsEvery = 12 * time.Hour

// listsView is what the page shows about the lists.
type listsView struct {
	Files []split.ListFile `json:"files"`
	Busy  bool             `json:"busy"`
	Error string           `json:"error"`
	// Missing: lists the rules name but the files do not have (or the
	// files are not downloaded yet).
	Missing []string `json:"missing"`
}

type listsState struct {
	dir    string
	loaded *split.Lists
	busy   bool
	err    string
	names  map[string][]string // file -> list names, for the page
}

func (a *app) listsDir() string {
	if a.lists.dir == "" {
		if dir, err := os.UserCacheDir(); err == nil {
			a.lists.dir = filepath.Join(dir, "TurnVK", "lists")
		}
	}
	return a.lists.dir
}

// listsView: a.mu is held.
func (a *app) listsView() listsView {
	v := listsView{Busy: a.lists.busy, Error: a.lists.err}
	if dir := a.listsDir(); dir != "" {
		v.Files = split.ListFiles(dir)
	}
	for _, r := range a.s.Split.Lists {
		if !r.Off && !a.lists.loaded.Has(r.List) {
			v.Missing = append(v.Missing, r.List)
		}
	}
	return v
}

// loadLists reads the lists the rules name and gives them to the router.
func (a *app) loadLists() {
	a.mu.Lock()
	dir, rules := a.listsDir(), slices.Clone(a.s.Split.Lists)
	a.mu.Unlock()
	if dir == "" {
		return
	}
	l, err := split.LoadLists(dir, rules)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		a.logf("lists: %v", err)
	}
	a.mu.Lock()
	a.lists.loaded = l
	rt := a.router
	on := a.s.Split.On
	a.mu.Unlock()
	if rt != nil {
		rt.SetLists(l)
		if on && len(l.Site) > 0 {
			split.FlushDNS()
		}
	}
	a.push()
}

// sameLists: the same lists are in use (their routes may differ).
func sameLists(a, b split.Rules) bool {
	key := func(r split.Rules) []string {
		var out []string
		for _, l := range r.Lists {
			if !l.Off {
				out = append(out, l.List)
			}
		}
		slices.Sort(out)
		return out
	}
	return slices.Equal(key(a), key(b))
}

// updateLists downloads the list files that changed at the source (a
// small checksum is fetched first). It runs only while e is connected.
func (a *app) updateLists(e *engine.Engine) {
	a.mu.Lock()
	if a.lists.busy || a.eng != e || e == nil {
		a.mu.Unlock()
		return
	}
	files := split.NeededFiles(a.s.Split.Lists)
	dir := a.listsDir()
	if len(files) == 0 || dir == "" {
		a.mu.Unlock()
		return
	}
	a.lists.busy, a.lists.err = true, ""
	a.mu.Unlock()
	a.push()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	go func() {
		select {
		case <-e.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	// A plain client: with the tunnel up, it goes through the VPN.
	c := &http.Client{Timeout: 10 * time.Minute}
	changed, err := split.UpdateLists(ctx, c, dir, files)
	cancel()

	a.mu.Lock()
	a.lists.busy = false
	if err != nil {
		a.lists.err = err.Error()
	}
	for _, f := range changed {
		delete(a.lists.names, f)
	}
	a.mu.Unlock()
	if err != nil {
		a.logf("lists: %v", err)
	}
	if len(changed) > 0 {
		a.logf("lists: updated %s", strings.Join(changed, ", "))
		a.loadLists()
	} else {
		a.push()
	}
}

// keepListsFresh updates the lists after connecting and every listsEvery
// while e stays connected.
func (a *app) keepListsFresh(e *engine.Engine) {
	t := time.NewTimer(5 * time.Second) // let the connection settle
	defer t.Stop()
	for {
		select {
		case <-e.Done():
			return
		case <-t.C:
		}
		a.updateLists(e)
		t.Reset(listsEvery)
	}
}

// listNames returns the lists a file has (cached until it changes).
func (a *app) listNames(file string) []string {
	a.mu.Lock()
	if n, ok := a.lists.names[file]; ok {
		a.mu.Unlock()
		return n
	}
	dir := a.listsDir()
	a.mu.Unlock()
	if dir == "" {
		return nil
	}
	n, err := split.ListNames(filepath.Join(dir, file))
	if err != nil {
		return nil
	}
	a.mu.Lock()
	if a.lists.names == nil {
		a.lists.names = map[string][]string{}
	}
	a.lists.names[file] = n
	a.mu.Unlock()
	return n
}
