module github.com/Jetvac/turn-vk-client

go 1.26.0

// captcha-auto is a local submodule (own go.mod). It's wired in here so the
// engine can run the automatic VK captcha solver without pulling the heavy
// tls-client dependency into the main module's build graph.
replace github.com/Jetvac/captcha-auto => ./captcha-auto

require (
	github.com/Jetvac/captcha-auto v0.0.0-00010101000000-000000000000
	github.com/jchv/go-webview2 v0.0.0-20260205173254-56598839c808
	github.com/pion/dtls/v3 v3.1.15
	github.com/pion/logging v0.2.4
	github.com/pion/turn/v5 v5.1.3
	golang.org/x/crypto v0.58.0
	golang.org/x/mobile v0.0.0-20261011034528-197770444867
	golang.zx2c4.com/wireguard v0.0.0-20261024220952-b3bc704ef0ee
)

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/bdandy/go-errors v1.2.2 // indirect
	github.com/bdandy/go-socks4 v1.2.3 // indirect
	github.com/bogdanfinn/fhttp v0.6.9 // indirect
	github.com/bogdanfinn/quic-go-utls v1.0.10-utls // indirect
	github.com/bogdanfinn/tls-client v1.16.0 // indirect
	github.com/bogdanfinn/utls v1.7.8-barnius // indirect
	github.com/bogdanfinn/websocket v1.5.6-barnius // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/jchv/go-winloader v0.0.0-20250406163304-c1995be93bd1 // indirect
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/stun/v4 v4.0.1 // indirect
	github.com/pion/transport/v5 v5.1.1 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/tam7t/hpkp v0.0.0-20160821193359-2b70b4024ed5 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)
