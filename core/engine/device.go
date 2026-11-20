package engine

// DeviceState is the device's battery and power state, sent with each
// minute of statistics (Config.Device): with it a night's reports tell how
// much battery the tunnel cost, and in which state (screen off, Doze).
type DeviceState struct {
	Batt     int  `json:"batt"`            // battery level, %
	Charging bool `json:"chg,omitempty"`   // on a charger
	Screen   bool `json:"screen"`          // the screen is on
	Doze     bool `json:"doze,omitempty"`  // Android's Doze (device idle)
	Saver    bool `json:"saver,omitempty"` // battery saver on
	// MAh: charge left (the battery's charge counter), mAh; finer than
	// Batt. MA: current now, mA (the sign differs between makers). 0:
	// not reported by this device.
	MAh int `json:"mah,omitempty"`
	MA  int `json:"ma,omitempty"`
}
