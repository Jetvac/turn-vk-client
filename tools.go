//go:build tools

// Package tools pins build tools: gomobile bind needs golang.org/x/mobile
// in the module graph.
package tools

import _ "golang.org/x/mobile/bind"
