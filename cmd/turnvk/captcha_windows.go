//go:build windows

package main

import (
	"context"
	"errors"
	"log"
	"runtime"
	"sync"

	webview2 "github.com/jchv/go-webview2"

	"github.com/Jetvac/turn-vk-client/core/vkcreds"
)

// webCaptcha opens VK's captcha page in a WebView2 window for the user to
// solve. A script on the page reports the success_token VK issues once the
// user passes the check; the window then closes by itself.
type webCaptcha struct{ mu sync.Mutex }

func newCaptchaSolver() vkcreds.CaptchaSolver { return &webCaptcha{} }

func (c *webCaptcha) SolveCaptcha(ctx context.Context, uri string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	type result struct {
		token string
		err   error
	}
	res := make(chan result, 1)
	ready := make(chan webview2.WebView, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		w := webview2.NewWithOptions(webview2.WebViewOptions{
			AutoFocus:     true,
			WindowOptions: webview2.WindowOptions{Title: "VK: подтвердите, что вы не робот", Width: 460, Height: 680, Center: true},
		})
		if w == nil {
			res <- result{err: errors.New("WebView2 is not available")}
			ready <- nil
			return
		}
		defer w.Destroy()
		_ = w.Bind("turnvkToken", func(token string) {
			select {
			case res <- result{token: token}:
			default:
			}
			w.Terminate()
		})
		w.Init(captchaHookJS)
		w.Navigate(uri)
		ready <- w
		w.Run()
		select {
		case res <- result{err: errors.New("the captcha window was closed")}:
		default:
		}
	}()
	w := <-ready
	log.Printf("captcha: solve it in the window that opened")
	select {
	case r := <-res:
		return r.token, r.err
	case <-ctx.Done():
		if w != nil {
			w.Dispatch(w.Terminate)
		}
		return "", ctx.Err()
	}
}

// captchaHookJS watches the page's own check request and passes the token
// VK returns to the app.
const captchaHookJS = `(function () {
  if (window.__turnvk) return; window.__turnvk = true;
  function report(data) {
    try {
      if (data && data.response && data.response.success_token) window.turnvkToken(data.response.success_token);
    } catch (e) {}
  }
  var f = window.fetch;
  window.fetch = function (input) {
    var url = typeof input === 'string' ? input : (input && input.url) || '';
    return f.apply(this, arguments).then(function (r) {
      if (url.indexOf('captchaNotRobot.check') >= 0) r.clone().json().then(report).catch(function () {});
      return r;
    });
  };
  var open = XMLHttpRequest.prototype.open, send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (m, url) { this.__u = url; return open.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function () {
    var x = this;
    if (String(x.__u || '').indexOf('captchaNotRobot.check') >= 0)
      x.addEventListener('load', function () { try { report(JSON.parse(x.responseText)); } catch (e) {} });
    return send.apply(this, arguments);
  };
})();`
