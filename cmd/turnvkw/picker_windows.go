//go:build windows

package main

import (
	"runtime"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The standard Windows dialogs for choosing a program or a folder for split
// tunneling rules.

var (
	comdlg32            = windows.NewLazySystemDLL("comdlg32.dll")
	getOpenFileName     = comdlg32.NewProc("GetOpenFileNameW")
	shell32             = windows.NewLazySystemDLL("shell32.dll")
	shBrowseForFolder   = shell32.NewProc("SHBrowseForFolderW")
	shGetPathFromIDList = shell32.NewProc("SHGetPathFromIDListW")
	ole32               = windows.NewLazySystemDLL("ole32.dll")
	coTaskMemFree       = ole32.NewProc("CoTaskMemFree")
)

// OPENFILENAMEW
type openFileName struct {
	structSize    uint32
	owner         uintptr
	instance      uintptr
	filter        *uint16
	customFilter  *uint16
	maxCustFilter uint32
	filterIndex   uint32
	file          *uint16
	maxFile       uint32
	fileTitle     *uint16
	maxFileTitle  uint32
	initialDir    *uint16
	title         *uint16
	flags         uint32
	fileOffset    uint16
	fileExtension uint16
	defExt        *uint16
	custData      uintptr
	hook          uintptr
	templateName  *uint16
	reserved      uintptr
	reserved2     uint32
	flagsEx       uint32
}

// BROWSEINFOW
type browseInfo struct {
	owner       uintptr
	root        uintptr
	displayName *uint16
	title       *uint16
	flags       uint32
	callback    uintptr
	param       uintptr
	image       int32
}

const (
	ofnNoChangeDir      = 0x8
	ofnPathMustExist    = 0x800
	ofnFileMustExist    = 0x1000
	ofnExplorer         = 0x80000
	ofnDontAddToRecent  = 0x2000000
	bifReturnOnlyFSDirs = 0x1
	bifNewDialogStyle   = 0x40
	bifNoNewFolder      = 0x200
)

// utf16z encodes s, which may hold NULs (filter lists do).
func utf16z(s string) *uint16 {
	u := append(utf16.Encode([]rune(s)), 0)
	return &u[0]
}

// pickPath shows the dialog and returns the chosen path, "" when cancelled.
// It runs on a thread of its own (the dialogs need COM in an STA).
func pickPath(owner unsafe.Pointer, folder bool) string {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED); err == nil {
		defer windows.CoUninitialize()
	}
	if folder {
		return pickFolder(uintptr(owner))
	}
	return pickFile(uintptr(owner))
}

func pickFile(owner uintptr) string {
	buf := make([]uint16, 4096)
	filter := "Программы (*.exe)\x00*.exe\x00Все файлы\x00*.*\x00"
	o := openFileName{
		owner:   owner,
		filter:  utf16z(filter),
		file:    &buf[0],
		maxFile: uint32(len(buf)),
		title:   utf16z("Программа для правила"),
		flags:   ofnNoChangeDir | ofnPathMustExist | ofnFileMustExist | ofnExplorer | ofnDontAddToRecent,
	}
	o.structSize = uint32(unsafe.Sizeof(o))
	if r, _, _ := getOpenFileName.Call(uintptr(unsafe.Pointer(&o))); r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}

func pickFolder(owner uintptr) string {
	name := make([]uint16, windows.MAX_PATH)
	b := browseInfo{
		owner:       owner,
		displayName: &name[0],
		title:       utf16z("Папка: все программы в ней и во вложенных папках"),
		flags:       bifReturnOnlyFSDirs | bifNewDialogStyle | bifNoNewFolder,
	}
	pidl, _, _ := shBrowseForFolder.Call(uintptr(unsafe.Pointer(&b)))
	if pidl == 0 {
		return ""
	}
	defer coTaskMemFree.Call(pidl)
	path := make([]uint16, 1024)
	if r, _, _ := shGetPathFromIDList.Call(pidl, uintptr(unsafe.Pointer(&path[0]))); r == 0 {
		return ""
	}
	return windows.UTF16ToString(path)
}
