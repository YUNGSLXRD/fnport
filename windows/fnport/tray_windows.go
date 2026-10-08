package main

import (
	"image/color"
	"runtime"
	"sync"
	"unsafe"

	"github.com/YUNGSLXRD/fnport/windows/internal/icon"
	"golang.org/x/sys/windows"
)

// The tray icon, straight on Win32 (Shell_NotifyIcon): a hidden window gets its clicks; the
// right-click menu turns fnport on and off and quits; balloons tell that the window went to tray.

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	pRegisterClassExW       = user32.NewProc("RegisterClassExW")
	pCreateWindowExW        = user32.NewProc("CreateWindowExW")
	pDefWindowProcW         = user32.NewProc("DefWindowProcW")
	pGetMessageW            = user32.NewProc("GetMessageW")
	pTranslateMessage       = user32.NewProc("TranslateMessage")
	pDispatchMessageW       = user32.NewProc("DispatchMessageW")
	pPostMessageW           = user32.NewProc("PostMessageW")
	pFindWindowW            = user32.NewProc("FindWindowW")
	pCreatePopupMenu        = user32.NewProc("CreatePopupMenu")
	pAppendMenuW            = user32.NewProc("AppendMenuW")
	pTrackPopupMenu         = user32.NewProc("TrackPopupMenu")
	pDestroyMenu            = user32.NewProc("DestroyMenu")
	pSetForegroundWindow    = user32.NewProc("SetForegroundWindow")
	pGetCursorPos           = user32.NewProc("GetCursorPos")
	pRegisterWindowMessageW = user32.NewProc("RegisterWindowMessageW")
	pCreateIconIndirect     = user32.NewProc("CreateIconIndirect")
	pDestroyIcon            = user32.NewProc("DestroyIcon")
	pGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	pShellNotifyIconW       = shell32.NewProc("Shell_NotifyIconW")
	pCreateBitmap           = gdi32.NewProc("CreateBitmap")
	pCreateDIBSection       = gdi32.NewProc("CreateDIBSection")
	pDeleteObject           = gdi32.NewProc("DeleteObject")
	pGetModuleHandleW       = kernel32.NewProc("GetModuleHandleW")
)

const (
	trayClass = "fnportTray"

	wmApp         = 0x8000
	wmTray        = wmApp + 1 // icon callbacks
	wmShow        = wmApp + 2 // another copy asks to show the window
	wmCommand     = 0x0111
	wmLButtonUp   = 0x0202
	wmRButtonUp   = 0x0205
	wmContextMenu = 0x007B
	wmNull        = 0x0000

	nimAdd    = 0
	nimModify = 1
	nimDelete = 2

	nifMessage = 0x1
	nifIcon    = 0x2
	nifTip     = 0x4
	nifInfo    = 0x10

	niifInfo    = 0x1
	niifNoSound = 0x10

	mfString    = 0x0
	mfSeparator = 0x800
	mfGrayed    = 0x1

	tpmRightButton = 0x2
	tpmReturnCmd   = 0x100
	tpmNoNotify    = 0x80

	cmdOpen   = 1
	cmdToggle = 2
	cmdQuit   = 3
)

type notifyIconData struct {
	Size            uint32
	Wnd             windows.Handle
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
	GUIDItem        windows.GUID
	BalloonIcon     windows.Handle
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type msg struct {
	Wnd     windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
	Private uint32
}

type tray struct {
	onOpen, onToggle, onQuit func()
	isOn                     func() bool

	mu         sync.Mutex
	wnd        windows.Handle
	icon       windows.Handle
	large      windows.Handle // for balloons
	tip        string
	accent     color.NRGBA
	taskbarMsg uint32
	ready      chan struct{}
}

func copyUTF16(dst []uint16, s string) {
	u, _ := windows.UTF16FromString(s)
	if len(u) > len(dst) {
		u = u[:len(dst)-1]
		u = append(u, 0)
	}
	copy(dst, u)
}

// makeIcon builds an HICON from our drawing: a 32-bit top-down DIB with alpha and an empty mask
func makeIcon(size int, accent color.NRGBA) windows.Handle {
	img := icon.Draw(size, accent)
	type bitmapInfoHeader struct {
		Size          uint32
		Width, Height int32
		Planes        uint16
		BitCount      uint16
		Compression   uint32
		SizeImage     uint32
		XPels, YPels  int32
		ClrUsed       uint32
		ClrImportant  uint32
	}
	bi := bitmapInfoHeader{Size: 40, Width: int32(size), Height: -int32(size), Planes: 1, BitCount: 32}
	var bits unsafe.Pointer
	hbm, _, _ := pCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if hbm == 0 || bits == nil {
		return 0
	}
	px := unsafe.Slice((*byte)(bits), size*size*4)
	for i := 0; i < size*size; i++ {
		// BGRA, premultiplied alpha
		r, g, b, a := img.Pix[i*4], img.Pix[i*4+1], img.Pix[i*4+2], img.Pix[i*4+3]
		px[i*4] = byte(uint32(b) * uint32(a) / 255)
		px[i*4+1] = byte(uint32(g) * uint32(a) / 255)
		px[i*4+2] = byte(uint32(r) * uint32(a) / 255)
		px[i*4+3] = a
	}
	mask, _, _ := pCreateBitmap.Call(uintptr(size), uintptr(size), 1, 1, 0)
	type iconInfo struct {
		Icon  int32
		X, Y  uint32
		Mask  windows.Handle
		Color windows.Handle
	}
	ii := iconInfo{Icon: 1, Mask: windows.Handle(mask), Color: windows.Handle(hbm)}
	h, _, _ := pCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	pDeleteObject.Call(hbm)
	pDeleteObject.Call(mask)
	return windows.Handle(h)
}

func smallIconSize() int {
	n, _, _ := pGetSystemMetrics.Call(49) // SM_CXSMICON
	if n < 16 || n > 64 {
		return 16
	}
	return int(n)
}

// run creates the hidden window and the icon, then serves their messages; call in a goroutine
func (t *tray) run() {
	runtime.LockOSThread()
	t.ready = make(chan struct{})
	inst, _, _ := pGetModuleHandleW.Call(0)
	cls, _ := windows.UTF16PtrFromString(trayClass)
	wc := wndClassEx{WndProc: windows.NewCallback(t.wndProc), Instance: windows.Handle(inst), ClassName: cls}
	wc.Size = uint32(unsafe.Sizeof(wc))
	pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	name, _ := windows.UTF16PtrFromString("fnport")
	w, _, _ := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(name)), 0, 0, 0, 0, 0, 0, 0, inst, 0)
	tbc, _ := windows.UTF16PtrFromString("TaskbarCreated")
	tm, _, _ := pRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(tbc)))

	t.mu.Lock()
	t.wnd, t.taskbarMsg = windows.Handle(w), uint32(tm)
	if t.accent == (color.NRGBA{}) {
		t.accent = icon.Gray
	}
	t.icon = makeIcon(smallIconSize(), t.accent)
	t.mu.Unlock()
	t.notify(nimAdd, nifMessage|nifIcon|nifTip, "", "")
	close(t.ready)

	var m msg
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func (t *tray) notify(op uint32, flags uint32, title, text string) {
	t.mu.Lock()
	nid := notifyIconData{Wnd: t.wnd, ID: 1, Flags: flags, CallbackMessage: wmTray, Icon: t.icon}
	copyUTF16(nid.Tip[:], t.tip)
	if flags&nifInfo != 0 {
		copyUTF16(nid.InfoTitle[:], title)
		copyUTF16(nid.Info[:], text)
		// Windows' own information icon: the app's icon is in the notification's header already
		nid.InfoFlags = niifInfo | niifNoSound
	}
	t.mu.Unlock()
	nid.Size = uint32(unsafe.Sizeof(nid))
	pShellNotifyIconW.Call(uintptr(op), uintptr(unsafe.Pointer(&nid)))
}

// set changes the icon's colour and tooltip
func (t *tray) set(accent color.NRGBA, tip string) {
	<-t.ready
	t.mu.Lock()
	if accent == t.accent && tip == t.tip {
		t.mu.Unlock()
		return
	}
	old := t.icon
	t.accent, t.tip = accent, tip
	t.icon = makeIcon(smallIconSize(), accent)
	t.mu.Unlock()
	t.notify(nimModify, nifIcon|nifTip, "", "")
	if old != 0 {
		pDestroyIcon.Call(uintptr(old))
	}
}

// balloon shows a notification next to the icon
func (t *tray) balloon(title, text string) {
	<-t.ready
	t.notify(nimModify, nifInfo, title, text)
}

func (t *tray) remove() {
	t.notify(nimDelete, 0, "", "")
}

func (t *tray) wndProc(hwnd, message, wParam, lParam uintptr) uintptr {
	switch uint32(message) {
	case wmTray:
		switch uint32(lParam) & 0xffff {
		case wmLButtonUp:
			go t.onOpen()
		case wmRButtonUp, wmContextMenu:
			t.menu(windows.Handle(hwnd))
		}
		return 0
	case wmShow:
		go t.onOpen()
		return 0
	}
	if t.taskbarMsg != 0 && uint32(message) == t.taskbarMsg {
		// Explorer restarted: the icon is gone, add it again
		t.notify(nimAdd, nifMessage|nifIcon|nifTip, "", "")
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, message, wParam, lParam)
	return r
}

func (t *tray) menu(hwnd windows.Handle) {
	m, _, _ := pCreatePopupMenu.Call()
	add := func(id int, s string, flags uintptr) {
		p, _ := windows.UTF16PtrFromString(s)
		pAppendMenuW.Call(m, flags, uintptr(id), uintptr(unsafe.Pointer(p)))
	}
	add(cmdOpen, "Открыть", mfString)
	if t.isOn() {
		add(cmdToggle, "Выключить", mfString)
	} else {
		add(cmdToggle, "Включить", mfString)
	}
	pAppendMenuW.Call(m, mfSeparator, 0, 0)
	add(cmdQuit, "Выход", mfString)
	var pt struct{ X, Y int32 }
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// the menu closes on a click elsewhere only if our window is in front
	pSetForegroundWindow.Call(uintptr(hwnd))
	cmd, _, _ := pTrackPopupMenu.Call(m, tpmRightButton|tpmReturnCmd|tpmNoNotify, uintptr(pt.X), uintptr(pt.Y), 0, uintptr(hwnd), 0)
	pPostMessageW.Call(uintptr(hwnd), wmNull, 0, 0)
	pDestroyMenu.Call(m)
	switch cmd {
	case cmdOpen:
		go t.onOpen()
	case cmdToggle:
		go t.onToggle()
	case cmdQuit:
		go t.onQuit()
	}
}

// otherInstance: if fnport already runs, ask it to show its window; true means "quit now"
func otherInstance() bool {
	name, _ := windows.UTF16PtrFromString("Local\\fnport-windows")
	_, err := windows.CreateMutex(nil, false, name)
	if err != windows.ERROR_ALREADY_EXISTS {
		return false
	}
	cls, _ := windows.UTF16PtrFromString(trayClass)
	if w, _, _ := pFindWindowW.Call(uintptr(unsafe.Pointer(cls)), 0); w != 0 {
		pPostMessageW.Call(w, wmShow, 0, 0)
	}
	return true
}
