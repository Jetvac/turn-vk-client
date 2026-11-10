package captchaauto

import (
	"context"

	"github.com/Jetvac/captcha-auto/profile"
)

// CaptchaSolver is the minimal contract the rest of the codebase expects from
// a captcha handler. SolveCaptcha solves a VK captcha and returns the success
// token VK issued, or an empty string when it was not solved.
//
// It never returns VK-specific rejection errors: on high-censorship networks
// VK keys off error strings and request timing, so the only observable outcome
// is "solved" or "not solved".
type CaptchaSolver interface {
	SolveCaptcha(ctx context.Context, redirectURI string) (string, error)
}

// CaptchaSolverAdapter adapts a Solver to the CaptchaSolver contract.
type CaptchaSolverAdapter struct {
	Solver *Solver
}

// SolveCaptcha solves the captcha at redirectURI. It returns the success token
// on success and an empty string (no error) when VK did not accept the answer.
func (a *CaptchaSolverAdapter) SolveCaptcha(ctx context.Context, redirectURI string) (string, error) {
	if a.Solver == nil {
		return "", nil
	}
	result := a.Solver.Solve(ctx, Challenge{RedirectURI: redirectURI})
	if result.Solved {
		return result.Token, nil
	}
	return "", nil
}

// CaptchaSolverFromProfile builds a CaptchaSolverAdapter. saved is an optional
// fingerprint to reuse; maxAttempts bounds retries per challenge.
func CaptchaSolverFromProfile(profile profile.Profile, saved *profile.SavedProfile, maxAttempts int) CaptchaSolver {
	return &CaptchaSolverAdapter{Solver: New(profile, saved, maxAttempts)}
}
