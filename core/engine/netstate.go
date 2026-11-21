package engine

// NetState is the physical network under the tunnel (the one VK's TURN
// servers are reached through), sent with each minute's statistics: a
// weak Wi-Fi, a slow mobile network or a network that keeps changing
// explains lag that the routes alone do not. Never the network's name.
type NetState struct {
	Kind string `json:"kind,omitempty"` // wifi, cell, eth, other, none ("": unknown)
	Cell string `json:"cell,omitempty"` // mobile network: 5g, lte, 3g, 2g
	RSSI int    `json:"rssi,omitempty"` // signal, dBm (Wi-Fi, or the mobile network's)
	// Bars: Android's signal level, 0 (none) to 4; nil: not known.
	Bars    *int `json:"bars,omitempty"`
	Quality int  `json:"q,omitempty"`    // Windows' Wi-Fi signal quality, %
	Mbps    int  `json:"mbps,omitempty"` // Wi-Fi link speed
	MHz     int  `json:"mhz,omitempty"`  // Wi-Fi channel frequency (2.4 or 5 GHz band)
	// Changes: times the network changed during the minute (the engine
	// counts them: Reconnect, SwitchNetwork).
	Changes uint64 `json:"chg,omitempty"`
}
