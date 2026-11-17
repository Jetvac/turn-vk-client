//go:build windows

// Command turnvkw is the Windows app: a window like the Android app's, and
// a system VPN through Wintun. It asks for administrator rights at start
// (Windows lets only administrators create network adapters).
package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"

	"github.com/Jetvac/turn-vk-client/core/winvpn"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

//go:embed ui.html
var page string

//go:embed wintun/amd64/wintun.dll
var wintunDLL []byte

func main() {
	if !winvpn.Elevated() {
		relaunchElevated()
		return
	}
	// One copy at a time: both would want the same network adapter.
	// After an update the old copy may still be closing: wait for it.
	afterUpdate := len(os.Args) > 1 && os.Args[1] == "--after-update"
	name, _ := windows.UTF16PtrFromString(`Global\TurnVK-app`)
	for try := 0; ; try++ {
		h, err := windows.CreateMutex(nil, false, name)
		if err != windows.ERROR_ALREADY_EXISTS {
			break
		}
		windows.CloseHandle(h)
		if !afterUpdate || try >= 50 {
			message("TurnVK уже запущен.", windows.MB_ICONINFORMATION)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	cleanupUpdate()
	if err := installWintun(); err != nil {
		message("Не удалось подготовить драйвер Wintun: "+err.Error(), windows.MB_ICONERROR)
		return
	}

	a := newApp()
	if a.crash != nil {
		// A panic leaves its trace here: the program has no console.
		_ = debug.SetCrashOutput(a.crash, debug.CrashOptions{})
	}
	a.logf("TurnVK %s started", version)
	dataPath := ""
	if dir, err := os.UserCacheDir(); err == nil {
		dataPath = filepath.Join(dir, "TurnVK", "webview")
	}
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		DataPath:  dataPath,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title: "TurnVK", Width: 440, Height: 780, Center: true, IconId: 1,
		},
	})
	if w == nil {
		message("Для окна TurnVK нужен Microsoft Edge WebView2 Runtime. Установите его с сайта Microsoft и запустите TurnVK снова.", windows.MB_ICONERROR)
		return
	}
	w.SetSize(400, 600, webview2.HintMin)
	a.w = w
	a.bind(w)
	w.SetHtml(page)

	stop := make(chan struct{})
	go a.tick(stop)
	go a.checkUpdates(stop)
	// "TurnVK.exe wdtt://..." adds (or selects) that server and connects.
	fromArg := false
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "wdtt://") {
			if err := a.addLink(arg); err != nil {
				a.logf("link from the command line: %v", err)
			} else {
				fromArg = true
			}
		}
	}
	a.mu.Lock()
	auto := (a.s.ConnectOnStart || fromArg) && a.current() != nil
	a.mu.Unlock()
	if other := winvpn.OtherVPN(); auto && other != "" {
		// The window explains it; connecting anyway is the user's call.
		a.logf("not connecting at start: another VPN (%s) is on", other)
		auto = false
	}
	if auto {
		go func() {
			if err := a.connect(); err != nil {
				a.logf("connect: %v", err)
				a.mu.Lock()
				a.lastErr = err.Error()
				a.mu.Unlock()
				a.push()
			}
		}()
	}

	w.Run()
	a.logf("window closed")
	close(stop)
	// The window is gone; free VK's allocations before the process ends.
	<-a.disconnect()
}

// relaunchElevated starts this program again with administrator rights
// (the UAC prompt) and lets this copy exit.
func relaunchElevated() {
	exe, err := os.Executable()
	if err != nil {
		message(err.Error(), windows.MB_ICONERROR)
		return
	}
	args := make([]string, 0, len(os.Args)-1)
	for _, a := range os.Args[1:] {
		args = append(args, syscall.EscapeArg(a))
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(args, " "))
	cwd, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err := windows.ShellExecute(0, verb, file, params, cwd, windows.SW_SHOWNORMAL); err != nil {
		if err == windows.ERROR_CANCELLED {
			message("TurnVK работает как VPN для всего компьютера, поэтому Windows просит разрешение администратора. Без него подключиться нельзя.", windows.MB_ICONINFORMATION)
			return
		}
		message("Не удалось запустить с правами администратора: "+err.Error(), windows.MB_ICONERROR)
	}
}

// installWintun puts wintun.dll next to the program, where the Wintun
// library looks for it (the program's folder or System32 only).
func installWintun() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	path := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if have, err := os.ReadFile(path); err == nil {
		a, b := sha256.Sum256(have), sha256.Sum256(wintunDLL)
		if bytes.Equal(a[:], b[:]) {
			return nil
		}
	}
	return os.WriteFile(path, wintunDLL, 0o644)
}

func message(text string, flags uint32) {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString("TurnVK")
	windows.MessageBox(0, t, c, flags)
}
