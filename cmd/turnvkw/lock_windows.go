//go:build windows

package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Any program the user runs can read the files in the user's profile.
// TurnVK's settings hold the servers' links (address, password, VK
// calls), which other programs, Russian apps among them, have no business
// reading. TurnVK itself always runs with administrator rights, so its
// settings folder is left to administrators and SYSTEM: a program started
// without elevation cannot open it. The owner becomes the Administrators
// group, and the OWNER RIGHTS entry takes away what an owner may do
// anyway (read and change the permissions), in case a file still gets
// the user as its owner.
const (
	lockedDirSDDL  = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x100000;;;OW)"
	lockedFileSDDL = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x100000;;;OW)"
)

// lockDir creates dir if needed and leaves it, and what is in it, to
// administrators and SYSTEM. New files inherit that.
func lockDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := setSecurity(dir, lockedDirSDDL); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		sddl := lockedFileSDDL
		if e.IsDir() {
			sddl = lockedDirSDDL
		}
		if err := setSecurity(filepath.Join(dir, e.Name()), sddl); err != nil {
			return err
		}
	}
	return nil
}

func setSecurity(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
}
