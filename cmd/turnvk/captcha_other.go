//go:build !windows

package main

import "github.com/Jetvac/turn-vk-client/core/vkcreds"

// On other systems the CLI has no browser window; VK captchas stop the
// credential request and it is retried later.
func newCaptchaSolver() vkcreds.CaptchaSolver { return nil }
