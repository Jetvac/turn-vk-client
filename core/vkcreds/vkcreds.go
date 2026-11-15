// Package vkcreds obtains TURN credentials of a VK call by joining it as an
// anonymous guest, the way the VK Calls web client does:
//
//  1. api.vk.me auth.getAnonymToken          → anonymous token
//  2. api.vk.me messages.getCallPreview      → user_id, secret
//  3. api.vk.me messages.getAnonymCallToken  → call token
//  4. calls.okcdn.ru auth.anonymLogin        → session key
//  5. calls.okcdn.ru vchat.joinConversationByLink → turn_server
//
// VK may answer steps 1–3 with a captcha (error 14). The captcha is shown
// to the user through a CaptchaSolver; nothing here solves it automatically.
// The tokens of steps 1–3 live for a day and are kept in a Cache, so a
// captcha comes up at most once a day per call: later credentials need
// only steps 4 and 5.
package vkcreds

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	callsClientID   = "8093730" // the VK Calls web client
	callsAPIHost    = "https://api.vk.me/method/"
	callsAPIVersion = "5.276"
	okAPI           = "https://calls.okcdn.ru/fb.do"
	okAppKey        = "CGMMEJLGDIHBABABA"
	joinBase        = "https://vk.ru/call/join/"
	userAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"

	// Lifetime is how long credentials are used for new allocations.
	// Allocations made with them keep working after that.
	Lifetime = 8 * time.Minute
	// Refresh is how often credentials with a known expiry are renewed.
	Refresh = time.Hour
	// minInterval spaces requests to VK so that several sessions starting
	// together do not hit its rate limits.
	minInterval = 2 * time.Second
	maxCaptchas = 3
)

// Creds are TURN credentials of one call.
type Creds struct {
	Username string
	Password string
	Servers  []string // host:port of UDP TURN servers
	Fetched  time.Time
	// Expires is when VK stops accepting the credentials (zero: unknown).
	Expires time.Time
}

// Fresh reports whether the credentials are still the ones to use for new
// allocations. Credentials with a known expiry (VK's are good for 8 hours)
// are renewed every Refresh; each renewal joins the call again, and VK
// answers too frequent joins with "flood".
func (c *Creds) Fresh() bool {
	if c.Expires.IsZero() {
		return time.Since(c.Fetched) < Lifetime
	}
	return time.Since(c.Fetched) < Refresh && c.Usable(30*time.Minute)
}

// Usable reports whether the credentials still work for new allocations
// at least for d.
func (c *Creds) Usable(d time.Duration) bool {
	if c.Expires.IsZero() {
		return time.Since(c.Fetched) < Lifetime
	}
	return time.Until(c.Expires) > d
}

// Captcha describes a captcha VK asked for.
type Captcha struct {
	RedirectURI string // page with the captcha, to be shown to the user
	sid         string
	ts          string
	attempt     string
}

// CaptchaSolver shows a captcha to the user and returns the success_token
// VK issued after the user solved it.
type CaptchaSolver interface {
	SolveCaptcha(ctx context.Context, redirectURI string) (string, error)
}

// ErrCaptchaRequired is returned when VK wants a captcha and there is no
// solver, or the user did not solve it.
var ErrCaptchaRequired = errors.New("VK requires a captcha")

// CallError means the call itself is unusable (ended, invalid link): the
// hash will not work until it is replaced.
type CallError struct {
	Code    int
	Message string
}

func (e *CallError) Error() string {
	return fmt.Sprintf("VK call is unavailable: %s (code %d)", e.Message, e.Code)
}

// APIError is any other error VK returned.
type APIError struct {
	Step    string
	Code    int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("VK %s: %s (code %d)", e.Step, e.Message, e.Code)
}

// RateLimited reports whether VK asked to slow down.
func (e *APIError) RateLimited() bool { return e.Code == 6 || e.Code == 9 || e.Code == 29 }

// Flood: VK refuses this guest more joins for a while
// (participant.check.flood); a fresh guest is let in at once.
func (e *APIError) Flood() bool { return strings.Contains(strings.ToLower(e.Message), "flood") }

// Client fetches credentials. It is safe for concurrent use; requests to VK
// are serialized.
type Client struct {
	HTTP    *http.Client
	Captcha CaptchaSolver
	Cache   *Cache
	Logf    func(format string, args ...any)

	once sync.Once
	sem  chan struct{} // one request sequence at a time; see lock
	last time.Time
}

// lock waits for the client's turn, or for ctx: a captcha the user is
// solving holds the client, and others give up when their time is up.
func (c *Client) lock(ctx context.Context) error {
	c.once.Do(func() { c.sem = make(chan struct{}, 1) })
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) unlock() { <-c.sem }

func (c *Client) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// Fetch joins the call with the given hash and returns its TURN credentials.
func (c *Client) Fetch(ctx context.Context, hash string) (*Creds, error) {
	return c.FetchAs(ctx, hash, 0)
}

// FetchAs is Fetch as guest number n of the call. VK limits the TURN
// allocations of one guest (about 16–20), so more sessions than that need
// more guests; each has its own saved tokens.
func (c *Client) FetchAs(ctx context.Context, hash string, n int) (*Creds, error) {
	if err := c.lock(ctx); err != nil {
		return nil, err
	}
	defer c.unlock()
	if wait := minInterval - time.Since(c.last); wait > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	defer func() { c.last = time.Now() }()

	key := hash
	if n > 0 {
		key = fmt.Sprintf("%s#%d", hash, n)
	}
	g := c.Cache.get(key)
	if g != nil {
		cr, err := c.join(ctx, hash, g)
		var ae *APIError
		if !errors.As(err, &ae) || ae.RateLimited() {
			return cr, err
		}
		// VK no longer takes the saved guest (expired, or it joined too
		// often): join as a new one.
		c.logf("VK call %.8s…: saved guest refused (%v), joining as a new one", hash, err)
		c.Cache.put(key, nil)
	}
	c.logf("VK call %.8s…: joining as new guest %d", hash, n+1)
	g, err := c.newGuest(ctx, hash)
	if err != nil {
		return nil, err
	}
	c.Cache.put(key, g)
	return c.join(ctx, hash, g)
}

// newGuest joins the call as a new anonymous guest (steps 1–3). These are
// the steps VK may ask a captcha for.
func (c *Client) newGuest(ctx context.Context, hash string) (*guest, error) {
	link := joinBase + hash
	g := &guest{Device: uuid(), Name: guestName()}
	r, err := c.callsAPI(ctx, "auth.getAnonymToken", url.Values{
		"client_id": {callsClientID}, "link": {link}, "device_id": {g.Device}, "anonymName": {g.Name},
	})
	if err != nil {
		return nil, err
	}
	if g.Anon, err = str(r, "response", "token"); err != nil {
		return nil, fmt.Errorf("VK getAnonymToken: %w", err)
	}
	if exp, err := num(r, "response", "expired_at"); err == nil {
		g.Expires, _ = strconv.ParseInt(exp, 10, 64)
	}
	if g.Expires == 0 {
		g.Expires = time.Now().Add(12 * time.Hour).Unix()
	}

	r, err = c.callsAPI(ctx, "messages.getCallPreview", url.Values{
		"anonymous_token": {g.Anon}, "device_id": {g.Device}, "extended": {"1"}, "fields": {"first_name,last_name"}, "link": {link},
	})
	if err != nil {
		return nil, err
	}
	userID, err := num(r, "response", "user_id")
	if err != nil {
		return nil, fmt.Errorf("VK getCallPreview: %w", err)
	}
	secret, err := str(r, "response", "secret")
	if err != nil {
		return nil, fmt.Errorf("VK getCallPreview: %w", err)
	}

	r, err = c.callsAPI(ctx, "messages.getAnonymCallToken", url.Values{
		"anonymous_token": {g.Anon}, "device_id": {g.Device}, "link": {link}, "name": {g.Name},
		"user_id": {userID}, "secret": {secret},
	})
	if err != nil {
		return nil, err
	}
	if g.Call, err = str(r, "response", "token"); err != nil {
		return nil, fmt.Errorf("VK getAnonymCallToken: %w", err)
	}
	return g, nil
}

// join gets TURN credentials for the guest (steps 4 and 5; no captcha).
func (c *Client) join(ctx context.Context, hash string, g *guest) (*Creds, error) {
	r, err := c.okAPI(ctx, "auth.anonymLogin", url.Values{
		"session_data": {fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":"1.0.1"}`, uuid())},
	})
	if err != nil {
		return nil, err
	}
	sessionKey, err := str(r, "session_key")
	if err != nil {
		return nil, fmt.Errorf("OK anonymLogin: %w", err)
	}

	r, err = c.okAPI(ctx, "vchat.joinConversationByLink", url.Values{
		"joinLink": {hash}, "isVideo": {"false"}, "protocolVersion": {"5"}, "anonymToken": {g.Call}, "session_key": {sessionKey},
	})
	if err != nil {
		return nil, err
	}
	cr := &Creds{Fetched: time.Now()}
	if cr.Username, err = str(r, "turn_server", "username"); err != nil {
		return nil, fmt.Errorf("OK joinConversationByLink: %w", err)
	}
	if cr.Password, err = str(r, "turn_server", "credential"); err != nil {
		return nil, fmt.Errorf("OK joinConversationByLink: %w", err)
	}
	ts, _ := r["turn_server"].(map[string]any)
	urls, _ := ts["urls"].([]any)
	cr.Servers = ParseTURNURLs(urls)
	if len(cr.Servers) == 0 {
		return nil, errors.New("VK returned no UDP TURN servers")
	}
	cr.Expires = turnExpiry(cr.Username)
	return cr, nil
}

// ParseTURNURLs keeps the UDP TURN servers of "turn:host:port?transport=udp".
func ParseTURNURLs(urls []any) []string {
	var out []string
	seen := map[string]bool{}
	for _, u := range urls {
		s, ok := u.(string)
		if !ok {
			continue
		}
		addr, query, _ := strings.Cut(s, "?")
		if strings.HasPrefix(addr, "turns:") || strings.Contains(query, "transport=tcp") {
			continue
		}
		addr = strings.TrimPrefix(addr, "turn:")
		if !strings.Contains(addr, ":") {
			addr += ":3478"
		}
		if addr != "" && !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
	}
	return out
}

// callsAPI calls an api.vk.me method, showing captchas to the user.
func (c *Client) callsAPI(ctx context.Context, method string, params url.Values) (map[string]any, error) {
	params.Set("v", callsAPIVersion)
	params.Set("lang", "en")
	for attempt := 0; ; attempt++ {
		r, err := c.post(ctx, callsAPIHost+method, params)
		if err != nil {
			return nil, err
		}
		e, ok := r["error"].(map[string]any)
		if !ok {
			return r, nil
		}
		code := intOf(e["error_code"])
		msg, _ := e["error_msg"].(string)
		switch {
		case code == 951 || code == 954 || (code >= 9000 && code <= 9999):
			return nil, &CallError{Code: code, Message: msg}
		case code != 14:
			return nil, &APIError{Step: method, Code: code, Message: msg}
		}
		cap := parseCaptcha(e)
		if c.Captcha == nil || cap.RedirectURI == "" {
			return nil, ErrCaptchaRequired
		}
		if attempt >= maxCaptchas {
			return nil, fmt.Errorf("%w: still asked after %d captchas", ErrCaptchaRequired, attempt)
		}
		c.logf("VK asks for a captcha (%s), waiting for the user", method)
		token, err := c.Captcha.SolveCaptcha(ctx, cap.RedirectURI)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCaptchaRequired, err)
		}
		if token == "" {
			return nil, ErrCaptchaRequired
		}
		att := cap.attempt
		if att == "" || att == "0" {
			att = "1"
		}
		params.Set("captcha_sid", cap.sid)
		params.Set("captcha_key", "")
		params.Set("success_token", token)
		params.Set("captcha_ts", cap.ts)
		params.Set("captcha_attempt", att)
		params.Set("is_sound_captcha", "0")
	}
}

func parseCaptcha(e map[string]any) Captcha {
	c := Captcha{RedirectURI: strOf(e["redirect_uri"]), sid: strOf(e["captcha_sid"]), ts: strOf(e["captcha_ts"]), attempt: strOf(e["captcha_attempt"])}
	return c
}

func (c *Client) okAPI(ctx context.Context, method string, params url.Values) (map[string]any, error) {
	params.Set("method", method)
	params.Set("format", "JSON")
	params.Set("application_key", okAppKey)
	r, err := c.post(ctx, okAPI, params)
	if err != nil {
		return nil, err
	}
	if code := intOf(r["error_code"]); code != 0 {
		msg, _ := r["error_msg"].(string)
		return nil, &APIError{Step: method, Code: code, Message: msg}
	}
	return r, nil
}

func (c *Client) post(ctx context.Context, endpoint string, params url.Values) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", "https://vk.ru")
	req.Header.Set("Referer", "https://vk.ru/")
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var r map[string]any
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("%s: HTTP %d, not JSON: %.120s", endpoint, resp.StatusCode, body)
	}
	return r, nil
}

func walk(r map[string]any, keys ...string) any {
	var cur any = r
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}

func str(r map[string]any, keys ...string) (string, error) {
	if s, ok := walk(r, keys...).(string); ok && s != "" {
		return s, nil
	}
	return "", fmt.Errorf("no %s in the answer", strings.Join(keys, "."))
}

func num(r map[string]any, keys ...string) (string, error) {
	switch v := walk(r, keys...).(type) {
	case float64:
		return strconv.FormatFloat(v, 'f', 0, 64), nil
	case string:
		if v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("no %s in the answer", strings.Join(keys, "."))
}

func strOf(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', 0, 64)
	}
	return ""
}

func intOf(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}

func uuid() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

var guestNames = []string{"Алексей", "Мария", "Дмитрий", "Анна", "Сергей", "Елена", "Иван", "Ольга", "Михаил", "Наталья", "Андрей", "Татьяна", "Павел", "Юлия", "Николай", "Ирина"}

func guestName() string { return guestNames[mrand.IntN(len(guestNames))] }
