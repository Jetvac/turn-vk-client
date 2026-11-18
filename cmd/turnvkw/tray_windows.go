//go:build windows

package main

// The notification area ("tray"): closing the window hides it and TurnVK
// keeps working; the icon opens the window again, and its menu connects,
// disconnects and quits. A second start of TurnVK shows the window of the
// running one.

import (
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	trayUser32  = windows.NewLazySystemDLL("user32.dll")
	trayShell32 = windows.NewLazySystemDLL("shell32.dll")

	procShellNotifyIcon    = trayShell32.NewProc("Shell_NotifyIconW")
	procSetWindowLongPtr   = trayUser32.NewProc("SetWindowLongPtrW")
	procCallWindowProc     = trayUser32.NewProc("CallWindowProcW")
	procDestroyWindow      = trayUser32.NewProc("DestroyWindow")
	procSetForeground      = trayUser32.NewProc("SetForegroundWindow")
	procIsWindowVisible    = trayUser32.NewProc("IsWindowVisible")
	procIsIconic           = trayUser32.NewProc("IsIconic")
	procCreatePopupMenu    = trayUser32.NewProc("CreatePopupMenu")
	procAppendMenu         = trayUser32.NewProc("AppendMenuW")
	procTrackPopupMenu     = trayUser32.NewProc("TrackPopupMenu")
	procDestroyMenu        = trayUser32.NewProc("DestroyMenu")
	procGetCursorPos       = trayUser32.NewProc("GetCursorPos")
	procPostMessage        = trayUser32.NewProc("PostMessageW")
	procLoadImage          = trayUser32.NewProc("LoadImageW")
	procGetSystemMetrics   = trayUser32.NewProc("GetSystemMetrics")
	procRegisterWindowMsg  = trayUser32.NewProc("RegisterWindowMessageW")
	procSetMenuDefaultItem = trayUser32.NewProc("SetMenuDefaultItem")
)

const (
	wmClose       = 0x0010
	wmCommand     = 0x0111
	wmNull        = 0x0000
	wmLButtonUp   = 0x0202
	wmLButtonDbl  = 0x0203
	wmRButtonUp   = 0x0205
	wmTray        = 0x8000 + 41 // WM_APP + 41
	wmShowWindow  = 0x8000 + 42 // posted by the show event's watcher
	nimAdd        = 0
	nimModify     = 1
	nimDelete     = 2
	nimSetVersion = 4
	nifMessage    = 0x1
	nifIcon       = 0x2
	nifTip        = 0x4
	nifInfo       = 0x10
	niifInfo      = 0x1
	gwlpWndProc   = ^uintptr(3) // -4
	mfString      = 0x0
	mfSeparator   = 0x800
	mfGrayed      = 0x1
	tpmReturnCmd  = 0x100
	tpmRightAlign = 0x8
	tpmBottom     = 0x20
	imageIcon     = 1
	smCxSmIcon    = 49
	smCySmIcon    = 50

	cmdOpen    = 1
	cmdConnect = 2
	cmdQuit    = 3
)

// notifyIconData is NOTIFYICONDATAW.
type notifyIconData struct {
	Size            uint32
	Wnd             windows.HWND
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            windows.Handle
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	Version         uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	GUID            windows.GUID
	BalloonIcon     windows.Handle
}

type tray struct {
	a        *app
	hwnd     uintptr
	prev     uintptr
	icon     windows.Handle
	created  uint32 // "TaskbarCreated": Explorer restarted, the icon is gone
	mu       sync.Mutex
	tip      string
	quitting bool
	added    bool
	shownFor string // the reason the window was last brought up for
}

var theTray *tray

// trayCallback must stay referenced: Windows calls it for the window's life.
var trayCallback = syscall.NewCallback(func(hwnd, msg, wp, lp uintptr) uintptr {
	return theTray.wndproc(hwnd, msg, wp, lp)
})

// startTray adds the icon and takes over the window's close button.
func startTray(a *app, hwnd uintptr) *tray {
	t := &tray{a: a, hwnd: hwnd}
	theTray = t
	name, _ := windows.UTF16PtrFromString("TaskbarCreated")
	r, _, _ := procRegisterWindowMsg.Call(uintptr(unsafe.Pointer(name)))
	t.created = uint32(r)
	var mod windows.Handle
	_ = windows.GetModuleHandleEx(0, nil, &mod)
	cx, _, _ := procGetSystemMetrics.Call(smCxSmIcon)
	cy, _, _ := procGetSystemMetrics.Call(smCySmIcon)
	ic, _, _ := procLoadImage.Call(uintptr(mod), 1, imageIcon, cx, cy, 0)
	t.icon = windows.Handle(ic)
	t.prev, _, _ = procSetWindowLongPtr.Call(hwnd, gwlpWndProc, trayCallback)
	t.tip = "TurnVK"
	t.add()
	return t
}

func (t *tray) data(flags uint32) *notifyIconData {
	d := &notifyIconData{Wnd: windows.HWND(t.hwnd), ID: 1, Flags: flags, CallbackMessage: wmTray, Icon: t.icon}
	d.Size = uint32(unsafe.Sizeof(*d))
	copyUTF16(d.Tip[:], t.tip)
	return d
}

func (t *tray) add() {
	t.mu.Lock()
	defer t.mu.Unlock()
	d := t.data(nifMessage | nifIcon | nifTip)
	r, _, _ := procShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(d)))
	t.added = r != 0
	d.Version = 4
	_, _, _ = procShellNotifyIcon.Call(nimSetVersion, uintptr(unsafe.Pointer(d)))
}

// remove takes the icon away (at exit; otherwise it stays until the mouse
// passes over it).
func (t *tray) remove() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, _, _ = procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(t.data(0))))
	t.added = false
}

// setTip shows the connection's state under the mouse.
func (t *tray) setTip(s string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if s == t.tip {
		return
	}
	t.tip = s
	_, _, _ = procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(t.data(nifTip))))
}

// balloon shows a notification next to the icon.
func (t *tray) balloon(title, text string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	d := t.data(nifInfo)
	copyUTF16(d.InfoTitle[:], title)
	copyUTF16(d.Info[:], text)
	d.InfoFlags = niifInfo
	_, _, _ = procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(d)))
}

func copyUTF16(dst []uint16, s string) {
	u, _ := windows.UTF16FromString(s)
	if len(u) > len(dst) {
		u = u[:len(dst)]
		u[len(u)-1] = 0
	}
	copy(dst, u)
}

// show brings the window back.
func (t *tray) show() {
	if v, _, _ := procIsIconic.Call(t.hwnd); v != 0 {
		_, _, _ = showWindow.Call(t.hwnd, windows.SW_RESTORE)
	} else {
		_, _, _ = showWindow.Call(t.hwnd, windows.SW_SHOW)
	}
	_, _, _ = procSetForeground.Call(t.hwnd)
}

// hide puts TurnVK in the background; the first time it says where it went.
func (t *tray) hide() {
	_, _, _ = showWindow.Call(t.hwnd, windows.SW_HIDE)
	t.a.mu.Lock()
	told := t.a.s.TrayTold
	if !told {
		t.a.s.TrayTold = true
		t.a.save()
	}
	t.a.mu.Unlock()
	if !told {
		t.balloon("TurnVK работает в фоне", "Значок TurnVK — рядом с часами. Выйти: правая кнопка мыши по значку → «Выйти».")
	}
}

// quit closes the window for real; main then disconnects and exits.
func (t *tray) quit() {
	t.mu.Lock()
	t.quitting = true
	t.mu.Unlock()
	_, _, _ = procDestroyWindow.Call(t.hwnd)
}

func (t *tray) wndproc(hwnd, msg, wp, lp uintptr) uintptr {
	switch {
	case msg == wmClose:
		t.mu.Lock()
		quitting := t.quitting
		t.mu.Unlock()
		t.a.mu.Lock()
		closeQuits := t.a.s.CloseQuits
		t.a.mu.Unlock()
		if !quitting && !closeQuits && t.added {
			t.hide()
			return 0
		}
	case msg == wmTray:
		switch uint32(lp) & 0xFFFF {
		case wmLButtonUp, wmLButtonDbl:
			t.show()
		case wmRButtonUp:
			t.menu()
		}
		return 0
	case msg == wmShowWindow:
		t.show()
		return 0
	case t.created != 0 && uint32(msg) == t.created:
		t.add()
	}
	r, _, _ := procCallWindowProc.Call(t.prev, hwnd, msg, wp, lp)
	return r
}

func (t *tray) menu() {
	m, _, _ := procCreatePopupMenu.Call()
	if m == 0 {
		return
	}
	defer procDestroyMenu.Call(m)
	item := func(id uintptr, flags uintptr, text string) {
		s, _ := windows.UTF16PtrFromString(text)
		_, _, _ = procAppendMenu.Call(m, flags, id, uintptr(unsafe.Pointer(s)))
	}
	t.a.mu.Lock()
	running, hasServer := t.a.eng != nil, t.a.current() != nil
	t.a.mu.Unlock()
	item(cmdOpen, mfString, "Открыть TurnVK")
	switch {
	case running:
		item(cmdConnect, mfString, "Отключить")
	case hasServer:
		item(cmdConnect, mfString, "Подключить")
	default:
		item(cmdConnect, mfString|mfGrayed, "Подключить")
	}
	item(0, mfSeparator, "")
	item(cmdQuit, mfString, "Выйти")
	_, _, _ = procSetMenuDefaultItem.Call(m, cmdOpen, 0)
	var pt struct{ X, Y int32 }
	_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// The menu closes when clicking elsewhere only if the window is in front.
	_, _, _ = procSetForeground.Call(t.hwnd)
	cmd, _, _ := procTrackPopupMenu.Call(m, tpmReturnCmd|tpmRightAlign|tpmBottom, uintptr(pt.X), uintptr(pt.Y), 0, t.hwnd, 0)
	_, _, _ = procPostMessage.Call(t.hwnd, wmNull, 0, 0)
	switch cmd {
	case cmdOpen:
		t.show()
	case cmdConnect:
		if running {
			go t.a.disconnect()
		} else {
			go func() {
				if err := t.a.connect(); err != nil {
					t.a.logf("connect: %v", err)
					t.a.mu.Lock()
					t.a.lastErr = err.Error()
					t.a.mu.Unlock()
					t.a.push()
					t.balloon("TurnVK не подключился", err.Error())
				}
			}()
		}
	case cmdQuit:
		t.quit()
	}
}

// The show event: a second start of TurnVK sets it, and the running one
// shows its window. Everyone may set it: the second start runs without
// administrator rights before it asks for them.
const showEventName = `Local\TurnVK-show`

// signalRunning asks a running TurnVK to show its window; false when none
// runs.
func signalRunning() bool {
	name, _ := windows.UTF16PtrFromString(showEventName)
	h, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, name)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	return windows.SetEvent(h) == nil
}

// watchShow waits for the show event and brings the window up.
func (t *tray) watchShow() {
	sd, err := windows.SecurityDescriptorFromString("D:(A;;0x1F0003;;;WD)S:(ML;;NW;;;LW)")
	if err != nil {
		return
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, _ := windows.UTF16PtrFromString(showEventName)
	h, err := windows.CreateEvent(sa, 0, 0, name)
	if err != nil {
		return
	}
	for {
		if ev, err := windows.WaitForSingleObject(h, windows.INFINITE); err != nil || ev != windows.WAIT_OBJECT_0 {
			return
		}
		_, _, _ = procPostMessage.Call(t.hwnd, wmShowWindow, 0, 0)
	}
}

// showOnce brings the window up once per reason ("" resets): for what
// needs the user, such as VK's check, while TurnVK is in the background.
func (t *tray) showOnce(reason string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	same := t.shownFor == reason
	t.shownFor = reason
	t.mu.Unlock()
	if same || reason == "" {
		return
	}
	if v, _, _ := procIsWindowVisible.Call(t.hwnd); v == 0 {
		_, _, _ = procPostMessage.Call(t.hwnd, wmShowWindow, 0, 0)
	}
}
