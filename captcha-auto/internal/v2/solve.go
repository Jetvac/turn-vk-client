package v2

import (
	"context"
	neturl "net/url"

	tlsclient "github.com/bogdanfinn/tls-client"

	"github.com/Jetvac/captcha-auto/profile"
)

// ParseChallenge extracts the redirect URI and session token from a VK captcha
// challenge. It returns nil when the redirect URI is unusable.
func ParseChallenge(redirectURI string) *VkCaptchaError {
	if redirectURI == "" {
		return nil
	}
	parsed, err := neturl.Parse(redirectURI)
	if err != nil {
		return nil
	}
	sessionToken := parsed.Query().Get("session_token")
	if redirectURI == "" {
		return nil
	}
	return &VkCaptchaError{RedirectURI: redirectURI, SessionToken: sessionToken}
}

// SolveVkCaptchaV2 is the internal entry point used by the public solver.
// It returns the success token, the captcha kind ("checkbox" or "slider") and
// an error. Callers of the public package treat any error as "not solved".
func SolveVkCaptchaV2(
	ctx context.Context,
	captchaErr *VkCaptchaError,
	client tlsclient.HttpClient,
	profile profile.Profile,
	savedProfile *profile.SavedProfile,
	maxAttempts int,
) (string, string, error) {
	return solveVkCaptchaV2Attempts(ctx, captchaErr, client, profile, savedProfile, maxAttempts)
}
