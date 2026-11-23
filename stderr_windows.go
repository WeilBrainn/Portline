//go:build windows

package main

import (
	"os"
	"syscall"
)

func redirectStderr(f *os.File) {
	const stdErrorHandle = ^uintptr(11) // -12 (STD_ERROR_HANDLE)
	kernel := syscall.NewLazyDLL("kernel32.dll")
	setStdHandle := kernel.NewProc("SetStdHandle")
	setStdHandle.Call(stdErrorHandle, f.Fd())
	os.Stderr = f
}
