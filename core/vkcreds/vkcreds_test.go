package vkcreds

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type fakeVK struct {
	captchaFor string // method that answers with a captcha until solved
	solvedWith url.Values
	callDead   bool
}

func (f *fakeVK) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		method := strings.TrimPrefix(r.URL.Path, "/method/")
		if r.URL.Path == "/fb.do" {
			method = r.Form.Get("method")
		}
		var out any
		switch method {
		case "auth.getAnonymToken":
			out = map[string]any{"response": map[string]any{"token": "anon"}}
		case "messages.getCallPreview":
			if f.callDead {
				out = map[string]any{"error": map[string]any{"error_code": 9000, "error_msg": "call ended"}}
				break
			}
			out = map[string]any{"response": map[string]any{"user_id": 123456789.0, "secret": "s3"}}
		case "messages.getAnonymCallToken":
			if f.captchaFor == method && r.Form.Get("success_token") == "" {
				out = map[string]any{"error": map[string]any{"error_code": 14, "error_msg": "Captcha needed",
					"captcha_sid": 987.0, "captcha_ts": 1700000000.0, "captcha_attempt": 1.0,
					"redirect_uri": "https://id.vk.ru/not_robot_captcha?session_token=abc"}}
				break
			}
			f.solvedWith = r.Form
			if r.Form.Get("user_id") != "123456789" || r.Form.Get("secret") != "s3" {
				t.Errorf("getAnonymCallToken got %v", r.Form)
			}
			out = map[string]any{"response": map[string]any{"token": "call"}}
		case "auth.anonymLogin":
			out = map[string]any{"session_key": "sk"}
		case "vchat.joinConversationByLink":
			if r.Form.Get("anonymToken") != "call" || r.Form.Get("session_key") != "sk" || r.Form.Get("joinLink") != "HASH" {
				t.Errorf("join got %v", r.Form)
			}
			out = map[string]any{"turn_server": map[string]any{"username": "u", "credential": "p", "urls": []any{
				"turn:1.2.3.4:3478?transport=udp", "turn:1.2.3.4:3478?transport=tcp", "turns:5.6.7.8:443", "turn:5.6.7.8:3478",
			}}}
		default:
			t.Errorf("unexpected method %q", method)
		}
		_ = json.NewEncoder(w).Encode(out)
	})
}

type solver struct {
	uri   string
	token string
	err   error
}

func (s *solver) SolveCaptcha(_ context.Context, uri string) (string, error) {
	s.uri = uri
	return s.token, s.err
}

// redirect sends the client's requests for the real hosts to the fake.
type redirect struct{ to string }

func (r redirect) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(r.to)
	req.URL.Scheme, req.URL.Host = u.Scheme, u.Host
	return http.DefaultTransport.RoundTrip(req)
}

func newClient(srv *httptest.Server, s CaptchaSolver) *Client {
	return &Client{HTTP: &http.Client{Transport: redirect{srv.URL}}, Captcha: s}
}

func TestFetch(t *testing.T) {
	f := &fakeVK{}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	c, err := newClient(srv, nil).Fetch(context.Background(), "HASH")
	if err != nil {
		t.Fatal(err)
	}
	if c.Username != "u" || c.Password != "p" || strings.Join(c.Servers, ",") != "1.2.3.4:3478,5.6.7.8:3478" {
		t.Fatalf("creds %+v", c)
	}
}

func TestCaptchaShownToUser(t *testing.T) {
	f := &fakeVK{captchaFor: "messages.getAnonymCallToken"}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	// No solver: the request stops with ErrCaptchaRequired.
	if _, err := newClient(srv, nil).Fetch(context.Background(), "HASH"); !errors.Is(err, ErrCaptchaRequired) {
		t.Fatalf("want ErrCaptchaRequired, got %v", err)
	}
	// The user gives up.
	if _, err := newClient(srv, &solver{err: errors.New("closed")}).Fetch(context.Background(), "HASH"); !errors.Is(err, ErrCaptchaRequired) {
		t.Fatalf("want ErrCaptchaRequired, got %v", err)
	}
	// The user solves it: the request is repeated with the token.
	s := &solver{token: "tok"}
	if _, err := newClient(srv, s).Fetch(context.Background(), "HASH"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.uri, "not_robot_captcha") {
		t.Fatalf("solver got %q", s.uri)
	}
	w := f.solvedWith
	if w.Get("success_token") != "tok" || w.Get("captcha_sid") != "987" || w.Get("captcha_ts") != "1700000000" || w.Get("captcha_attempt") != "1" {
		t.Fatalf("retry params %v", w)
	}
}

func TestCallUnavailable(t *testing.T) {
	srv := httptest.NewServer((&fakeVK{callDead: true}).handler(t))
	defer srv.Close()
	_, err := newClient(srv, nil).Fetch(context.Background(), "HASH")
	var ce *CallError
	if !errors.As(err, &ce) || ce.Code != 9000 {
		t.Fatalf("want CallError, got %v", err)
	}
}
