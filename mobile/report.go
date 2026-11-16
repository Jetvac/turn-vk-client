//go:build linux || android

package mobile

import (
	"context"
	"runtime"
	"strings"
	"time"

	"github.com/Jetvac/turn-vk-client/core/diag"
	"github.com/Jetvac/turn-vk-client/core/link"
)

// Report builds the diagnostic report for developers. system, settings
// and logs are lines separated by "\n" from the app. It runs network checks
// for a few seconds: call it off the main thread.
//
// The checks test the network the engine itself uses (VK's DNS and API):
// the app is left out of its own VPN, so checks through the tunnel are not
// possible here; the tunnel's handshake and traffic show whether it works.
func Report(app, system, settings, rawLink, lastError, logs string) string {
	r := &diag.Report{
		App:      app,
		System:   append(lines(system), "engine: "+runtime.Version()+" "+runtime.GOOS+"/"+runtime.GOARCH),
		Settings: lines(settings),
		Link:     rawLink,
		Error:    lastError,
		Log:      lines(logs),
	}
	mu.Lock()
	e := current
	mu.Unlock()
	if e != nil {
		st, d := e.Status(), e.Diag()
		r.Status, r.Diag = &st, &d
	}
	opts := diag.CheckOptions{}
	if l, err := link.Parse(rawLink); err == nil {
		opts.Server = l.Host
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r.Checks = diag.RunChecks(ctx, opts)
	return r.Text()
}

func lines(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Split(strings.TrimRight(s, "\n"), "\n")
}
