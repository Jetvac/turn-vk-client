//go:build windows

package main

import (
	"log"

	"github.com/Jetvac/turn-vk-client/core/vkcreds"
	"github.com/Jetvac/turn-vk-client/core/webcaptcha"
)

func newCaptchaSolver() vkcreds.CaptchaSolver { return webcaptcha.New(log.Printf) }
