//go:build windows

package main

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var dialogOLE = windows.NewLazySystemDLL("ole32.dll")
var dialogCoInit = dialogOLE.NewProc("CoInitializeEx")
var dialogCoUninit = dialogOLE.NewProc("CoUninitialize")
var dialogCreate = dialogOLE.NewProc("CoCreateInstance")
var dialogMemFree = dialogOLE.NewProc("CoTaskMemFree")

type configDialogCOM struct{ vt *[29]uintptr }

func (o *configDialogCOM) release() { syscall.SyscallN(o.vt[2], uintptr(unsafe.Pointer(o))) }
func dialogFailed(hr uintptr) bool  { return int32(uint32(hr)) < 0 }

// Native IFileOpenDialog, on a dedicated STA thread. No shell/PowerShell or
// subprocess receives the chosen path or configuration contents.
func pickNativeAWGFile(owner uintptr) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fail := func() (string, error) {
		return "", errors.New("не удалось открыть окно выбора файла")
	}
	hr, _, _ := dialogCoInit.Call(0, 2)
	if dialogFailed(hr) {
		return fail()
	}
	defer dialogCoUninit.Call()
	clsid, _ := windows.GUIDFromString("{DC1C5A9C-E88A-4DDE-A5A1-60F82A20AEF7}")
	iid, _ := windows.GUIDFromString("{D57C7288-D4AD-4768-BE02-9D969532D960}")
	var dialog *configDialogCOM
	hr, _, _ = dialogCreate.Call(uintptr(unsafe.Pointer(&clsid)), 0, 1, uintptr(unsafe.Pointer(&iid)), uintptr(unsafe.Pointer(&dialog)))
	if dialogFailed(hr) || dialog == nil {
		return fail()
	}
	defer dialog.release()
	// IFileDialog.SetOptions: filesystem-only, existing file/path, preserve CWD,
	// and do not add sensitive configuration paths to Recent Documents.
	hr, _, _ = syscall.SyscallN(dialog.vt[9], uintptr(unsafe.Pointer(dialog)), 0x40|0x800|0x1000|0x8|0x2000000)
	if dialogFailed(hr) {
		return fail()
	}
	name, _ := windows.UTF16PtrFromString("AmneziaWG (*.conf)")
	pattern, _ := windows.UTF16PtrFromString("*.conf")
	filter := struct{ name, pattern *uint16 }{name, pattern}
	hr, _, _ = syscall.SyscallN(dialog.vt[4], uintptr(unsafe.Pointer(dialog)), 1, uintptr(unsafe.Pointer(&filter)))
	if dialogFailed(hr) {
		return fail()
	}
	title, _ := windows.UTF16PtrFromString("Импорт конфигурации AmneziaWG")
	hr, _, _ = syscall.SyscallN(dialog.vt[17], uintptr(unsafe.Pointer(dialog)), uintptr(unsafe.Pointer(title)))
	if dialogFailed(hr) {
		return fail()
	}
	hr, _, _ = syscall.SyscallN(dialog.vt[3], uintptr(unsafe.Pointer(dialog)), owner)
	runtime.KeepAlive(filter)
	runtime.KeepAlive(title)
	if uint32(hr) == 0x800704c7 {
		return "", nil
	} // User cancelled.
	if dialogFailed(hr) {
		return fail()
	}
	var item *configDialogCOM
	hr, _, _ = syscall.SyscallN(dialog.vt[20], uintptr(unsafe.Pointer(dialog)), uintptr(unsafe.Pointer(&item)))
	if dialogFailed(hr) || item == nil {
		return fail()
	}
	defer item.release()
	var path *uint16
	// IShellItem.GetDisplayName(SIGDN_FILESYSPATH).
	hr, _, _ = syscall.SyscallN(item.vt[5], uintptr(unsafe.Pointer(item)), 0x80058000, uintptr(unsafe.Pointer(&path)))
	if dialogFailed(hr) || path == nil {
		return fail()
	}
	defer dialogMemFree.Call(uintptr(unsafe.Pointer(path)))
	return windows.UTF16PtrToString(path), nil
}
