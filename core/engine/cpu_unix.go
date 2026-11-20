//go:build unix

package engine

import (
	"syscall"
	"time"
)

// processCPU is the CPU time the process used so far (user and system);
// on Android the whole app, Kotlin included.
func processCPU() time.Duration {
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}
