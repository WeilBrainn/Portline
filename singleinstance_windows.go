//go:build windows

package main

import (
	"errors"
	"syscall"
	"unsafe"
)

// Only one Portline instance per Windows session may control shared routes.
// Windows releases the named mutex even if the application crashes.
func acquireAppInstance() (func(), error) {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	create := kernel.NewProc("CreateMutexW")
	closeHandle := kernel.NewProc("CloseHandle")
	name, err := syscall.UTF16PtrFromString(`Local\PortlineTunnelController`)
	if err != nil {
		return nil, err
	}
	handle, _, lastErr := create.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if handle == 0 {
		return nil, errors.New("cannot acquire Portline Windows session lock: " + lastErr.Error())
	}
	if lastErr == syscall.Errno(183) {
		closeHandle.Call(handle)
		if notifyExistingInstance() {
			return nil, errExistingInstanceNotified
		}
		return nil, errors.New("Portline уже запущен. Используй открытое окно программы или значок в трее.")
	}
	return func() { closeHandle.Call(handle) }, nil
}

func notifyStartupFailure(msg string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	messageBox := user32.NewProc("MessageBoxW")
	text, _ := syscall.UTF16PtrFromString(msg)
	title, _ := syscall.UTF16PtrFromString("Portline")
	messageBox.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), 0x10)
}
