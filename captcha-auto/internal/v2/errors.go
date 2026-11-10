package v2

import (
	neturl "net/url"
	"strconv"
	"strings"
)

// VkCaptchaError describes a VK captcha challenge extracted from a VK API
// error. Only the fields the solver needs are decoded; the rest are dropped so
// nothing identifiable leaks out of the package.
type VkCaptchaError struct {
	RedirectURI    string
	SessionToken   string
	CaptchaTs      string
	CaptchaAttempt string
}

// Domain is the VK domain the captcha belongs to (vk.com by default).
func (e *VkCaptchaError) Domain() string { return captchaDomainFromRedirectURI(e.RedirectURI) }

func captchaDomainFromRedirectURI(redirectURI string) string {
	const fallback = "vk.com"
	parsed, err := neturl.Parse(redirectURI)
	if err != nil {
		return fallback
	}
	domain := strings.TrimSpace(parsed.Query().Get("domain"))
	if domain == "" {
		return fallback
	}
	return domain
}

// parseVkCaptchaError turns a VK API error object into a VkCaptchaError. It
// keeps only RedirectURI, SessionToken, CaptchaTs and CaptchaAttempt — the
// public contract returns none of these, only whether the captcha was solved.
func parseVkCaptchaError(errData map[string]interface{}) *VkCaptchaError {
	redirectUri, _ := errData["redirect_uri"].(string)

	captchaSid, _ := errData["captcha_sid"].(string)
	if captchaSid == "" {
		if sidNum, ok := errData["captcha_sid"].(float64); ok {
			captchaSid = strconv.FormatFloat(sidNum, 'f', 0, 64)
		}
	}

	var sessionToken string
	if redirectUri != "" {
		if parsed, err := neturl.Parse(redirectUri); err == nil {
			sessionToken = parsed.Query().Get("session_token")
		}
	}

	var captchaTs string
	if tsFloat, ok := errData["captcha_ts"].(float64); ok {
		captchaTs = strconv.FormatFloat(tsFloat, 'f', 0, 64)
	} else if tsStr, ok := errData["captcha_ts"].(string); ok {
		captchaTs = tsStr
	}

	var captchaAttempt string
	if attFloat, ok := errData["captcha_attempt"].(float64); ok {
		captchaAttempt = strconv.FormatFloat(attFloat, 'f', 0, 64)
	} else if attStr, ok := errData["captcha_attempt"].(string); ok {
		captchaAttempt = attStr
	}

	if redirectUri == "" {
		return nil
	}
	return &VkCaptchaError{
		RedirectURI:    redirectUri,
		SessionToken:   sessionToken,
		CaptchaTs:      captchaTs,
		CaptchaAttempt: captchaAttempt,
	}
}
