//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Starting with Windows: a task in the Task Scheduler that runs
// "TurnVK.exe --autostart" when the user signs in, with the highest
// privileges. A Run key in the registry would ask for administrator rights
// (UAC) at every sign-in; a task with the highest privileges does not.

const taskName = "TurnVK"

// autostart is set by "--autostart": the app was started by the task.
var autostart bool

// schtasks runs the Task Scheduler's command line tool.
func schtasks(args ...string) (string, error) {
	cmd := exec.Command("schtasks", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// autostartEnabled reports whether the task exists.
func autostartEnabled() bool {
	_, err := schtasks("/Query", "/TN", taskName)
	return err == nil
}

// setAutostart creates (or replaces) the task, or deletes it.
func setAutostart(on bool) error {
	if !on {
		if !autostartEnabled() {
			return nil
		}
		if out, err := schtasks("/Delete", "/TN", taskName, "/F"); err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	u, err := user.Current()
	if err != nil {
		return err
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	xmlPath := filepath.Join(dir, "TurnVK", "autostart.xml")
	_ = os.MkdirAll(filepath.Dir(xmlPath), 0o700)
	if err := os.WriteFile(xmlPath, utf16File(taskXML(u.Username, exe)), 0o600); err != nil {
		return err
	}
	defer os.Remove(xmlPath)
	if out, err := schtasks("/Create", "/TN", taskName, "/XML", xmlPath, "/F"); err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

// taskXML: at the user's sign-in, after 10 seconds, with the highest
// privileges, on batteries too, with no time limit, one copy at a time.
func taskXML(userName, exe string) string {
	esc := func(s string) string {
		r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
		return r.Replace(s)
	}
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>TurnVK: start and connect when you sign in to Windows.</Description></RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><UserId>` + esc(userName) + `</UserId><Delay>PT10S</Delay></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>` + esc(userName) + `</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>` + esc(exe) + `</Command><Arguments>--autostart</Arguments><WorkingDirectory>` + esc(filepath.Dir(exe)) + `</WorkingDirectory></Exec>
  </Actions>
</Task>
`
}

// utf16File encodes s as UTF-16 LE with a byte order mark, as schtasks
// expects of an XML file that says encoding="UTF-16".
func utf16File(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2+2*len(u))
	b[0], b[1] = 0xFF, 0xFE
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2+2*i:], c)
	}
	return b
}

// refreshAutostart keeps the task pointing at this program, which may have
// moved since the task was made; a.mu is not held.
func (a *app) refreshAutostart() {
	if !autostartEnabled() {
		a.mu.Lock()
		changed := a.s.Autostart
		a.s.Autostart = false
		if changed {
			a.save()
		}
		a.mu.Unlock()
		return
	}
	a.mu.Lock()
	a.s.Autostart = true
	a.mu.Unlock()
	if err := setAutostart(true); err != nil {
		a.logf("start with Windows: updating the task: %v", err)
	}
}

// waitForNetwork: right after sign-in the network may not be up yet.
// Waits until VK's name resolves, for up to two minutes.
func (a *app) waitForNetwork() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for first := true; ; first = false {
		c, cc := context.WithTimeout(ctx, 3*time.Second)
		_, err := net.DefaultResolver.LookupHost(c, "api.vk.com")
		cc()
		if err == nil {
			if !first {
				a.logf("the network is up")
			}
			return
		}
		if first {
			a.logf("waiting for the network before connecting")
		}
		select {
		case <-ctx.Done():
			a.logf("no network after two minutes; connecting anyway")
			return
		case <-time.After(3 * time.Second):
		}
	}
}

// minimize puts the window in the taskbar (started with Windows: the user
// did not ask to see it).
func minimize(hwnd unsafe.Pointer) {
	if hwnd != nil {
		_, _, _ = showWindow.Call(uintptr(hwnd), windows.SW_MINIMIZE)
	}
}

var showWindow = windows.NewLazySystemDLL("user32.dll").NewProc("ShowWindow")
