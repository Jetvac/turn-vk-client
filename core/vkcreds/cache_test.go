package vkcreds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// guestVK answers the five steps and counts the calls of each.
type guestVK struct {
	mu        sync.Mutex
	calls     map[string]int
	callToken string
	rejectOld bool // joinConversationByLink refuses tokens other than callToken
}

func (f *guestVK) RoundTrip(r *http.Request) (*http.Response, error) {
	_ = r.ParseForm()
	method := strings.TrimPrefix(r.URL.Path, "/method/")
	if r.URL.Host == "calls.okcdn.ru" {
		method = r.PostForm.Get("method")
	}
	f.mu.Lock()
	f.calls[method]++
	f.mu.Unlock()
	var out any
	switch method {
	case "auth.getAnonymToken":
		out = map[string]any{"response": map[string]any{"token": "anon", "expired_at": time.Now().Add(24 * time.Hour).Unix()}}
	case "messages.getCallPreview":
		out = map[string]any{"response": map[string]any{"user_id": 5, "secret": "s"}}
	case "messages.getAnonymCallToken":
		out = map[string]any{"response": map[string]any{"token": f.callToken}}
	case "auth.anonymLogin":
		out = map[string]any{"session_key": "k"}
	case "vchat.joinConversationByLink":
		if f.rejectOld && r.PostForm.Get("anonymToken") != f.callToken {
			out = map[string]any{"error_code": 102, "error_msg": "token expired"}
			break
		}
		exp := time.Now().Add(8 * time.Hour).Unix()
		out = map[string]any{"turn_server": map[string]any{
			"username": fmt.Sprintf("%d:42", exp), "credential": "pw",
			"urls": []any{"turn:1.2.3.4:19302?transport=udp"},
		}}
	}
	rec := httptest.NewRecorder()
	_ = json.NewEncoder(rec).Encode(out)
	res := rec.Result()
	res.Body = io.NopCloser(strings.NewReader(rec.Body.String()))
	return res, nil
}

func (f *guestVK) count(m string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[m]
}

func TestGuestReused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vk.json")
	f := &guestVK{calls: map[string]int{}, callToken: "call1"}
	newClient := func() *Client {
		c := &Client{HTTP: &http.Client{Transport: f}, Cache: &Cache{Path: path}}
		c.last = time.Now().Add(-time.Hour)
		return c
	}
	c := newClient()
	ctx := context.Background()
	cr, err := c.Fetch(ctx, "hash")
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(cr.Expires) < 7*time.Hour || !cr.Usable(time.Hour) {
		t.Fatalf("expiry %v", cr.Expires)
	}
	c.last = time.Time{}
	if _, err := c.Fetch(ctx, "hash"); err != nil {
		t.Fatal(err)
	}
	// A new run of the app reads the saved guest.
	if _, err := newClient().Fetch(ctx, "hash"); err != nil {
		t.Fatal(err)
	}
	if n := f.count("auth.getAnonymToken"); n != 1 {
		t.Fatalf("guest joined %d times, want 1", n)
	}
	if n := f.count("vchat.joinConversationByLink"); n != 3 {
		t.Fatalf("%d joins", n)
	}

	// VK no longer takes the saved token: one new guest, then on.
	f.mu.Lock()
	f.callToken, f.rejectOld = "call2", true
	f.mu.Unlock()
	if _, err := newClient().Fetch(ctx, "hash"); err != nil {
		t.Fatal(err)
	}
	if n := f.count("auth.getAnonymToken"); n != 2 {
		t.Fatalf("after rejection: %d guests, want 2", n)
	}
	if _, err := newClient().Fetch(ctx, "hash"); err != nil {
		t.Fatal(err)
	}
	if n := f.count("auth.getAnonymToken"); n != 2 {
		t.Fatalf("replacement guest not saved: %d guests", n)
	}
}

func TestGuestExpiry(t *testing.T) {
	c := &Cache{}
	c.put("a", &guest{Call: "x", Expires: time.Now().Add(10 * time.Minute).Unix()})
	c.put("b", &guest{Call: "y", Expires: time.Now().Add(5 * time.Hour).Unix()})
	if c.get("a") != nil {
		t.Fatal("guest about to expire was used")
	}
	if g := c.get("b"); g == nil || g.Call != "y" {
		t.Fatal("valid guest not found")
	}
	var nilCache *Cache
	nilCache.put("a", &guest{})
	if nilCache.get("a") != nil {
		t.Fatal("nil cache")
	}
	if !turnExpiry("abc").IsZero() || turnExpiry("1794754421:585547250792").Unix() != 1794754421 {
		t.Fatal("turnExpiry")
	}
	old := &Creds{Fetched: time.Now().Add(-time.Hour)}
	if old.Usable(0) {
		t.Fatal("credentials without expiry outlived Lifetime")
	}
}

func TestCredsSaved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vk.json")
	c := &Cache{Path: path}
	c.put("h", &guest{Call: "x", Expires: time.Now().Add(5 * time.Hour).Unix()})
	good := &Creds{Username: "u", Password: "p", Servers: []string{"1.2.3.4:3478"}, Fetched: time.Now(), Expires: time.Now().Add(7 * time.Hour)}
	c.PutCreds("h#0/0", good)
	c.PutCreds("h#0/1", &Creds{Username: "old", Fetched: time.Now().Add(-8 * time.Hour), Expires: time.Now().Add(30 * time.Minute)})

	again := &Cache{Path: path}
	if cr := again.Creds("h#0/0"); cr == nil || cr.Username != "u" || len(cr.Servers) != 1 || !cr.Fresh() {
		t.Fatalf("saved credentials: %+v", cr)
	}
	if again.Creds("h#0/1") != nil {
		t.Fatal("credentials about to expire were handed out")
	}
	if again.get("h") == nil {
		t.Fatal("guest lost when credentials were saved")
	}
	again.PutCreds("h#0/0", nil)
	if (&Cache{Path: path}).Creds("h#0/0") != nil {
		t.Fatal("forgotten credentials came back")
	}

	// A file in the first layout (guests only) still loads.
	old := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(old, []byte(`{"h":{"call":"c","expires":`+fmt.Sprint(time.Now().Add(5*time.Hour).Unix())+`}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if g := (&Cache{Path: old}).get("h"); g == nil || g.Call != "c" {
		t.Fatal("old cache file not read")
	}
}
