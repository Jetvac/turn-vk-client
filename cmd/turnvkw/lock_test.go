//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/Jetvac/turn-vk-client/core/winvpn"
)

func TestLockedSDDL(t *testing.T) {
	for _, s := range []string{lockedDirSDDL, lockedFileSDDL} {
		sd, err := windows.SecurityDescriptorFromString(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		owner, _, err := sd.Owner()
		if err != nil || !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			t.Fatalf("%s: owner %v %v", s, owner, err)
		}
		if ctl, _, _ := sd.Control(); ctl&windows.SE_DACL_PROTECTED == 0 {
			t.Fatalf("%s: inherits the profile's permissions", s)
		}
	}
}

// A program without elevation can neither read a file with these
// permissions nor give itself access back, even when it owns the file
// (OWNER RIGHTS). Run without elevation; the owner is left as it is.
func TestLockedFileKeepsOutUser(t *testing.T) {
	if winvpn.Elevated() {
		t.Skip("elevated: administrators may read it")
	}
	f := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(f, []byte("wdtt://secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	dacl := func(sddl string) *windows.ACL {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		d, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	locked := dacl(lockedFileSDDL[len("O:BA"):])
	if err := windows.SetNamedSecurityInfo(f, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, locked, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(f); err == nil {
		t.Fatal("read a locked file")
	}
	open := dacl("D:P(A;;FA;;;WD)")
	if err := windows.SetNamedSecurityInfo(f, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, open, nil); err == nil {
		t.Fatal("the owner gave itself access back")
	}
	if err := os.Remove(f); err != nil { // the folder's owner may still delete it
		t.Fatal(err)
	}
}

// The folder and a file already in it end up with administrators and
// SYSTEM only (run elevated; skipped otherwise).
func TestLockDir(t *testing.T) {
	if !winvpn.Elevated() {
		t.Skip("needs administrator rights")
	}
	dir := filepath.Join(t.TempDir(), "TurnVK")
	os.MkdirAll(dir, 0o700)
	f := filepath.Join(dir, "settings.json")
	os.WriteFile(f, []byte("{}"), 0o600)
	if err := lockDir(dir); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "new.json"), []byte("{}"), 0o600)
	me, _ := windows.GetCurrentProcessToken().GetTokenUser()
	for _, p := range []string{dir, f, filepath.Join(dir, "new.json")} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		s := sd.String()
		if strings.Contains(s, me.User.Sid.String()) || !strings.Contains(s, "BA") || !strings.Contains(s, "SY") {
			t.Fatalf("%s: %s", p, s)
		}
	}
}
