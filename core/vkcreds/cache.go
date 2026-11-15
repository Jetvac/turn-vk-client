package vkcreds

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Cache keeps the guest identity VK issued for each call: the anonymous
// token and the call token live for a day, and only getting them can bring
// up a captcha. With them cached, fresh TURN credentials need only the
// calls.okcdn.ru steps, which never ask for one. With a Path the cache
// survives restarts of the app.
type Cache struct {
	Path string

	mu     sync.Mutex
	loaded bool
	guests map[string]*guest
	creds  map[string]*Creds
}

// cacheFile is the file's layout.
type cacheFile struct {
	Guests map[string]*guest `json:"guests"`
	Creds  map[string]*Creds `json:"creds,omitempty"`
}

// Creds returns saved TURN credentials still usable for an hour, or nil.
// key names one group of sessions (the engine chooses it).
func (c *Cache) Creds(key string) *Creds {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadLocked()
	cr := c.creds[key]
	if cr == nil || !cr.Usable(time.Hour) {
		return nil
	}
	cp := *cr
	return &cp
}

// PutCreds saves (or with nil forgets) the TURN credentials of a group.
func (c *Cache) PutCreds(key string, cr *Creds) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadLocked()
	if cr == nil {
		if _, ok := c.creds[key]; !ok {
			return
		}
		delete(c.creds, key)
	} else {
		cp := *cr
		c.creds[key] = &cp
	}
	c.saveLocked()
}

// guest is one anonymous participant of a call.
type guest struct {
	Device  string `json:"device"`
	Name    string `json:"name"`
	Anon    string `json:"anon"`
	Call    string `json:"call"`
	Expires int64  `json:"expires"` // unix seconds
}

// guestMargin: a guest this close to expiry is replaced, so that it does
// not run out in the middle of a fetch.
const guestMargin = 30 * time.Minute

func (c *Cache) get(hash string) *guest {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadLocked()
	g := c.guests[hash]
	if g == nil || time.Until(time.Unix(g.Expires, 0)) < guestMargin {
		return nil
	}
	cp := *g
	return &cp
}

func (c *Cache) put(hash string, g *guest) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadLocked()
	if g == nil {
		delete(c.guests, hash)
	} else {
		cp := *g
		c.guests[hash] = &cp
	}
	c.saveLocked()
}

func (c *Cache) loadLocked() {
	if c.loaded {
		return
	}
	c.loaded = true
	c.guests = map[string]*guest{}
	c.creds = map[string]*Creds{}
	if c.Path == "" {
		return
	}
	b, err := os.ReadFile(c.Path)
	if err != nil {
		return
	}
	var f cacheFile
	if json.Unmarshal(b, &f) == nil && f.Guests != nil {
		c.guests = f.Guests
		if f.Creds != nil {
			c.creds = f.Creds
		}
	} else {
		// The first layout: guests only.
		_ = json.Unmarshal(b, &c.guests)
		if c.guests == nil {
			c.guests = map[string]*guest{}
		}
	}
	now := time.Now().Unix()
	for h, g := range c.guests {
		if g == nil || g.Expires <= now {
			delete(c.guests, h)
		}
	}
	for k, cr := range c.creds {
		if cr == nil || !cr.Usable(0) {
			delete(c.creds, k)
		}
	}
}

func (c *Cache) saveLocked() {
	if c.Path == "" {
		return
	}
	b, err := json.Marshal(cacheFile{Guests: c.guests, Creds: c.creds})
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(c.Path), 0o700)
	tmp := c.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, c.Path)
}

// turnExpiry reads the expiry from a TURN username of the "expiry:user"
// form VK uses; zero if it has another form.
func turnExpiry(username string) time.Time {
	ts, _, ok := strings.Cut(username, ":")
	if !ok {
		return time.Time{}
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || n < 1e9 {
		return time.Time{}
	}
	return time.Unix(n, 0)
}
