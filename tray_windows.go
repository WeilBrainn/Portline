//go:build windows

package main

import (
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

const (
	wmDestroy     = 0x0002
	wmCommand     = 0x0111
	wmLButtonUp   = 0x0202
	wmLButtonDbl  = 0x0203
	wmRButtonUp   = 0x0205
	wmContextMenu = 0x007B
	wmApp         = 0x8000
	wmTrayIcon    = wmApp + 1
	wmShowUI      = wmApp + 2
	wmQuitTray    = wmApp + 3

	nimAdd    = 0x00000000
	nimDelete = 0x00000002

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004

	mfString    = 0x00000000
	mfSeparator = 0x00000800
	mfGrayed    = 0x00000001

	tpmRightButton = 0x0002
	tpmBottomAlign = 0x0020

	cmdTrayOpen       = 1001
	cmdTrayDisconnect = 1002
	cmdTrayExit       = 1003

	trayWindowClass = "PortlineTrayWindow"
)

var (
	trayUser32   = syscall.NewLazyDLL("user32.dll")
	trayShell32  = syscall.NewLazyDLL("shell32.dll")
	trayKernel32 = syscall.NewLazyDLL("kernel32.dll")
	trayGdi32    = syscall.NewLazyDLL("gdi32.dll")

	procRegisterClassExW   = trayUser32.NewProc("RegisterClassExW")
	procCreateWindowExW    = trayUser32.NewProc("CreateWindowExW")
	procDefWindowProcW     = trayUser32.NewProc("DefWindowProcW")
	procGetMessageW        = trayUser32.NewProc("GetMessageW")
	procTranslateMessage   = trayUser32.NewProc("TranslateMessage")
	procDispatchMessageW   = trayUser32.NewProc("DispatchMessageW")
	procPostMessageW       = trayUser32.NewProc("PostMessageW")
	procPostQuitMessage    = trayUser32.NewProc("PostQuitMessage")
	procDestroyWindow      = trayUser32.NewProc("DestroyWindow")
	procFindWindowW        = trayUser32.NewProc("FindWindowW")
	procCreatePopupMenu    = trayUser32.NewProc("CreatePopupMenu")
	procAppendMenuW        = trayUser32.NewProc("AppendMenuW")
	procTrackPopupMenu     = trayUser32.NewProc("TrackPopupMenu")
	procDestroyMenu        = trayUser32.NewProc("DestroyMenu")
	procSetForegroundWin   = trayUser32.NewProc("SetForegroundWindow")
	procGetCursorPos       = trayUser32.NewProc("GetCursorPos")
	procLoadIconW          = trayUser32.NewProc("LoadIconW")
	procCreateIconIndirect = trayUser32.NewProc("CreateIconIndirect")
	procDestroyIcon        = trayUser32.NewProc("DestroyIcon")

	procShellNotifyIconW = trayShell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandleW = trayKernel32.NewProc("GetModuleHandleW")

	procCreateDIBSection = trayGdi32.NewProc("CreateDIBSection")
	procCreateBitmap     = trayGdi32.NewProc("CreateBitmap")
	procDeleteObject     = trayGdi32.NewProc("DeleteObject")
)

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type point struct {
	x, y int32
}

type msg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

type notifyIconDataW struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         [16]byte
	hBalloonIcon     uintptr
}

type bitmapInfoHeader struct {
	biSize          uint32
	biWidth         int32
	biHeight        int32
	biPlanes        uint16
	biBitCount      uint16
	biCompression   uint32
	biSizeImage     uint32
	biXPelsPerMeter int32
	biYPelsPerMeter int32
	biClrUsed       uint32
	biClrImportant  uint32
}

type iconInfo struct {
	fIcon    int32
	xHotspot uint32
	yHotspot uint32
	hbmMask  uintptr
	hbmColor uintptr
}

func createPortlineTrayIcon() uintptr {
	const size = 16
	hdr := bitmapInfoHeader{
		biSize:     uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		biWidth:    size,
		biHeight:   -size, // top-down
		biPlanes:   1,
		biBitCount: 32,
	}
	var bits unsafe.Pointer
	hColor, _, _ := procCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&hdr)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if hColor == 0 || bits == nil {
		icon, _, _ := procLoadIconW.Call(0, 32512) // IDI_APPLICATION
		return icon
	}
	defer procDeleteObject.Call(hColor)

	pixels := unsafe.Slice((*uint32)(bits), size*size)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			// Rounded dark slate badge (#0c1622) with 1px border (#38536b).
			corner := (x == 0 || x == size-1) && (y == 0 || y == size-1)
			if corner {
				pixels[y*size+x] = 0x00000000
				continue
			}
			border := x == 0 || x == size-1 || y == 0 || y == size-1
			if border {
				pixels[y*size+x] = 0xFF38536B
			} else {
				pixels[y*size+x] = 0xFF0C1622
			}
		}
	}
	// Draw Portline's 3 bars (left tall, middle medium, right short).
	drawBar := func(x0, x1, y0, y1 int, col uint32) {
		for y := y0; y <= y1; y++ {
			for x := x0; x <= x1; x++ {
				pixels[y*size+x] = col
			}
		}
	}
	drawBar(3, 5, 3, 12, 0xFF72B7DC)
	drawBar(7, 9, 6, 12, 0xFFB1D8EE)
	drawBar(11, 13, 9, 12, 0xFF87C7EA)

	var maskBits [size * 2]byte
	hMask, _, _ := procCreateBitmap.Call(size, size, 1, 1, uintptr(unsafe.Pointer(&maskBits[0])))
	if hMask == 0 {
		icon, _, _ := procLoadIconW.Call(0, 32512)
		return icon
	}
	defer procDeleteObject.Call(hMask)

	ii := iconInfo{fIcon: 1, hbmMask: hMask, hbmColor: hColor}
	hIcon, _, _ := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	if hIcon == 0 {
		icon, _, _ := procLoadIconW.Call(0, 32512)
		return icon
	}
	return hIcon
}

type trayController struct {
	hwnd     uintptr
	hIcon    uintptr
	url      string
	app      *App
	onQuit   func()
	quitOnce sync.Once
}

var activeTray *trayController

func startTray(url string, app *App, onQuit func()) func() {
	ready := make(chan uintptr, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		hInst, _, _ := procGetModuleHandleW.Call(0)
		className, _ := syscall.UTF16PtrFromString(trayWindowClass)
		hIcon := createPortlineTrayIcon()

		tc := &trayController{hIcon: hIcon, url: url, app: app, onQuit: onQuit}
		activeTray = tc

		wndProc := syscall.NewCallback(func(hwnd, uMsg, wParam, lParam uintptr) uintptr {
			switch uint32(uMsg) {
			case wmTrayIcon:
				switch uint32(lParam) {
				case wmLButtonUp, wmLButtonDbl:
					go openUI(tc.url)
				case wmRButtonUp, wmContextMenu:
					tc.showContextMenu(hwnd)
				}
				return 0
			case wmShowUI:
				go openUI(tc.url)
				return 0
			case wmCommand:
				switch wParam & 0xFFFF {
				case cmdTrayOpen:
					go openUI(tc.url)
				case cmdTrayDisconnect:
					go tc.disconnectTunnel()
				case cmdTrayExit:
					tc.triggerQuit(hwnd)
				}
				return 0
			case wmQuitTray:
				tc.removeIcon(hwnd)
				procDestroyWindow.Call(hwnd)
				return 0
			case wmDestroy:
				tc.removeIcon(hwnd)
				procPostQuitMessage.Call(0)
				return 0
			}
			ret, _, _ := procDefWindowProcW.Call(hwnd, uMsg, wParam, lParam)
			return ret
		})

		wc := wndClassExW{
			cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
			lpfnWndProc:   wndProc,
			hInstance:     hInst,
			lpszClassName: className,
		}
		procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

		hwnd, _, _ := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(className)), 0, 0, 0, 0, 0, 0, 0, hInst, 0)
		tc.hwnd = hwnd
		if hwnd != 0 {
			nid := notifyIconDataW{
				cbSize:           uint32(unsafe.Sizeof(notifyIconDataW{})),
				hWnd:             hwnd,
				uID:              1,
				uFlags:           nifMessage | nifIcon | nifTip,
				uCallbackMessage: wmTrayIcon,
				hIcon:            hIcon,
			}
			tip, _ := syscall.UTF16FromString("Portline VPN")
			copy(nid.szTip[:], tip)
			procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
		}
		ready <- hwnd

		var m msg
		for {
			ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
			if int32(ret) <= 0 {
				break
			}
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}
		if hIcon != 0 {
			procDestroyIcon.Call(hIcon)
		}
	}()

	hwnd := <-ready
	return func() {
		if hwnd != 0 {
			procPostMessageW.Call(hwnd, wmQuitTray, 0, 0)
		}
	}
}

func (tc *trayController) removeIcon(hwnd uintptr) {
	nid := notifyIconDataW{
		cbSize: uint32(unsafe.Sizeof(notifyIconDataW{})),
		hWnd:   hwnd,
		uID:    1,
	}
	procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
}

func (tc *trayController) triggerQuit(hwnd uintptr) {
	tc.removeIcon(hwnd)
	procDestroyWindow.Call(hwnd)
	tc.quitOnce.Do(func() {
		if tc.onQuit != nil {
			go tc.onQuit()
		}
	})
}

func (tc *trayController) disconnectTunnel() {
	tc.app.mu.Lock()
	if tc.app.tunnelBusy {
		if tc.app.wantConnected {
			tc.app.wantConnected = false
		}
		tc.app.mu.Unlock()
		return
	}
	tc.app.tunnelBusy = true
	tc.app.mu.Unlock()
	tc.app.runTunnelTask("disconnect")
}

func (tc *trayController) showContextMenu(hwnd uintptr) {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)

	openLabel, _ := syscall.UTF16PtrFromString("Открыть Portline")
	procAppendMenuW.Call(menu, mfString, cmdTrayOpen, uintptr(unsafe.Pointer(openLabel)))

	tc.app.mu.Lock()
	active := tc.app.nativeSession != nil || tc.app.wantConnected
	tc.app.mu.Unlock()
	discFlags := uintptr(mfString)
	if !active {
		discFlags |= mfGrayed
	}
	discLabel, _ := syscall.UTF16PtrFromString("Отключить VPN")
	procAppendMenuW.Call(menu, discFlags, cmdTrayDisconnect, uintptr(unsafe.Pointer(discLabel)))

	procAppendMenuW.Call(menu, mfSeparator, 0, 0)
	exitLabel, _ := syscall.UTF16PtrFromString("Выход")
	procAppendMenuW.Call(menu, mfString, cmdTrayExit, uintptr(unsafe.Pointer(exitLabel)))

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWin.Call(hwnd)
	procTrackPopupMenu.Call(menu, tpmRightButton|tpmBottomAlign, uintptr(pt.x), uintptr(pt.y), 0, hwnd, 0)
	procPostMessageW.Call(hwnd, 0, 0, 0)
}

func notifyExistingInstance() bool {
	className, err := syscall.UTF16PtrFromString(trayWindowClass)
	if err != nil {
		return false
	}
	hwnd, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(className)), 0)
	if hwnd == 0 {
		return false
	}
	procPostMessageW.Call(hwnd, wmShowUI, 0, 0)
	return true
}
