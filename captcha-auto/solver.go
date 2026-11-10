// Package captcha-auto is a self-contained automatic solver for VK Smart
// Captcha (the "are you not a robot" PoW, slider and checkbox variants) that
// VK serves when handing out TURN credentials from a call.
//
// The public contract is intentionally tiny: Solve reports only whether the
// captcha was solved and which kind. VK on high-censorship networks reacts to
// error strings and request timing, so internal rejections are swallowed — the
// caller sees a plain "not solved" result and nothing identifiable.
package captchaauto

import (
	"context"
	"log"

	tlsclient "github.com/bogdanfinn/tls-client"

	"github.com/Jetvac/captcha-auto/internal/v2"
	"github.com/Jetvac/captcha-auto/profile"
)

// CapType names the kind of captcha that was solved.
type CapType string

const (
	// CapTypeCheckbox is a click-the-box captcha.
	CapTypeCheckbox CapType = "checkbox"
	// CapTypeSlider is the image-puzzle slider captcha.
	CapTypeSlider CapType = "slider"
)

// Challenge is a VK captcha challenge as the caller sees it.
type Challenge struct {
	// RedirectURI is the VK page that carries the captcha. SessionToken is
	// derived from it when empty.
	RedirectURI string
}

// Result is the outcome of solving a challenge.
type Result struct {
	// Token is the success_token VK issued, or empty when not solved.
	Token string
	// Solved reports whether a success_token was obtained.
	Solved bool
	// Type is the captcha kind that was solved, or "" when not solved.
	Type CapType
}

// Solver solves VK captcha challenges.
type Solver struct {
	client   tlsclient.HttpClient
	profile  profile.Profile
	saved    *profile.SavedProfile
	maxAtts  int
}

// New builds a Solver. profile is the impersonation identity; saved is an
// optional fingerprint to reuse; maxAttempts bounds retries per challenge.
func New(profile profile.Profile, saved *profile.SavedProfile, maxAttempts int) *Solver {
	if maxAttempts < 1 {
		maxAttempts = 10
	}
	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithCookieJar(tlsclient.NewCookieJar()))
	if err != nil {
		log.Printf("[CAPTCHA] tls-client init failed: %v; using default", err)
		client, err = tlsclient.NewHttpClient(tlsclient.NewNoopLogger())
	}
	return &Solver{client: client, profile: profile, saved: saved, maxAtts: maxAttempts}
}

// Solve attempts to solve the challenge. It returns Solved=false (never an
// error) unless ctx is canceled or the request cannot be formed structurally.
func (s *Solver) Solve(ctx context.Context, ch Challenge) Result {
	captchaErr := v2.ParseChallenge(ch.RedirectURI)
	if captchaErr == nil {
		log.Printf("[CAPTCHA] missing session_token in redirect_uri: %q", ch.RedirectURI)
		return Result{}
	}
	token, capType, err := v2.SolveVkCaptchaV2(ctx, captchaErr, s.client, s.profile, s.saved, s.maxAtts)
	if err != nil {
		log.Printf("[CAPTCHA] solve failed: %v", err)
		return Result{}
	}
	return Result{Token: token, Solved: token != "", Type: CapType(capType)}
}
