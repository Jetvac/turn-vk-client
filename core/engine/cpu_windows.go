package engine

import (
	"time"

	"golang.org/x/sys/windows"
)

// processCPU is the CPU time the process used so far (user and kernel).
func processCPU() time.Duration {
	var c, e, k, u windows.Filetime
	if windows.GetProcessTimes(windows.CurrentProcess(), &c, &e, &k, &u) != nil {
		return 0
	}
	// Filetime counts 100 ns units.
	ft := func(f windows.Filetime) time.Duration {
		return time.Duration(uint64(f.HighDateTime)<<32|uint64(f.LowDateTime)) * 100
	}
	return ft(k) + ft(u)
}
