# captcha-auto

Self-contained automatic solver for VK Smart Captcha — the "are you not a
robot" PoW, slider (image puzzle) and checkbox challenges that VK serves when
handing out TURN credentials from a call.

This is a standalone submodule. It keeps the heavy browser-impersonation
dependency (`bogdanfinn/tls-client`) out of the main project by living in its
own module and being wired in with a `replace` directive.

## Contract

The public surface is deliberately tiny. The only thing VK on high-censorship
networks can react to is error strings and request timing, so the module never
returns VK rejection errors:

```go
result := solver.Solve(ctx, captchaauto.Challenge{RedirectURI: redirectURI})
if result.Solved {
    // result.Token is the success_token VK issued — the proof of passing.
    // result.Type is the captcha kind ("checkbox" or "slider").
    _ = result.Token
    _ = result.Type
}
// On "not solved" result.Solved is false and Token is empty; there is no error.
```

The adapter to the codebase's own `CaptchaSolver` contract:

```go
solver := captchaauto.CaptchaSolverFromProfile(profile.Chrome, nil, 10)
token, err := solver.SolveCaptcha(ctx, redirectURI) // token = success_token, err only on ctx cancel
```

## Layout

```
captcha-auto/
  go.mod                 own module (tls-client + fhttp + uuid)
  solver.go              public contract: Solver, Challenge, Result
  adapter.go             CaptchaSolver adapter (the (string, error) contract)
  profile/               browser impersonation profiles (UA + Sec-CH-* headers)
  internal/v2/
    captcha.go           PoW + orchestration (settings → slider/checkbox → check → endSession)
    slider.go            slider solver: decode + rank guesses + fake cursor
    errors.go            VkCaptchaError parsing (internal only)
    constants.go         shared types/constants
    solve.go             internal wrapper
    v2_test.go           unit tests
```

## Build

```bash
cd captcha-auto
go mod download
go mod tidy          # populate go.sum from the network; needs module proxy access
go test ./...
```

`go mod tidy` must run from this directory because the dependencies live here.
The main project adds this module via `replace github.com/Jetvac/captcha-auto => ./captcha-auto`
in its own `go.mod` and imports `github.com/Jetvac/captcha-auto`.

## Notes

- The impersonation is done per-request in `applyBrowserProfileFhttp` (UA +
  `Sec-CH-*` headers), so it does not depend on the tls-client client-profile
  API shape.
- Retries are bounded (`maxAttempts`); a rate-limited captcha session sleeps and
  retries within that budget.
- The slider solver ranks candidates by seam-based luma/RGB/text scores and
  submits them in consensus order, faking a cursor trajectory.
