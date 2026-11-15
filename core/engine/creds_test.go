package engine

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Jetvac/turn-vk-client/core/link"
	"github.com/Jetvac/turn-vk-client/core/vkcreds"
)

// captchaVK answers every VK request with a captcha.
type captchaVK struct{}

func (captchaVK) RoundTrip(*http.Request) (*http.Response, error) {
	body := `{"error":{"error_code":14,"error_msg":"Captcha needed","redirect_uri":"https://id.vk.ru/not_robot","captcha_sid":"1"}}`
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
}

// waitingUser never solves the captcha; it counts the times it was asked.
type waitingUser struct{ asked atomic.Int32 }

func (u *waitingUser) SolveCaptcha(ctx context.Context, _ string) (string, error) {
	u.asked.Add(1)
	<-ctx.Done()
	return "", ctx.Err()
}

func TestCredsNotHeldByCaptcha(t *testing.T) {
	user := &waitingUser{}
	e, err := New(Config{Link: link.Link{Host: "127.0.0.1", WGPort: 1, Password: "p", Hashes: []string{"hash"}}, DeviceID: "d", Captcha: user})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.ctx = ctx
	e.state = StateConnected
	e.vk.HTTP = &http.Client{Transport: captchaVK{}}
	hs := e.hashes[0]

	// Credentials past their refresh time, still valid at VK.
	old := &vkcreds.Creds{Username: "u", Servers: []string{"1.2.3.4:3478"}, Fetched: time.Now().Add(-time.Hour), Expires: time.Now().Add(7 * time.Hour)}
	hs.slot(0).cur.Store(old)
	for i := 0; i < 3; i++ {
		start := time.Now()
		c, err := hs.get(ctx, e, 0)
		if err != nil || c != old {
			t.Fatalf("get: %v %v", c, err)
		}
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Fatalf("waited %v for the captcha", d)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for user.asked.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := user.asked.Load(); n != 1 {
		t.Fatalf("captcha shown %d times, want 1 (one background refresh)", n)
	}
	if st := e.Status(); !st.Captcha || st.State != StateCaptcha {
		t.Fatalf("status with no session: %+v", st)
	}

	// Expired credentials are not handed out.
	hs.slot(1).cur.Store(&vkcreds.Creds{Fetched: time.Now().Add(-9 * time.Hour), Expires: time.Now().Add(-time.Hour)})
	short, stop := context.WithTimeout(ctx, 200*time.Millisecond)
	defer stop()
	if _, err := hs.get(short, e, 1); err == nil {
		t.Fatal("expired credentials used")
	}
}
