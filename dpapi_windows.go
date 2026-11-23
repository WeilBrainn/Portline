//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32                = syscall.NewLazyDLL("Crypt32.dll")
	kernel32               = syscall.NewLazyDLL("Kernel32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree          = kernel32.NewProc("LocalFree")
)

const cryptprotectUIForbidden = 0x1

func bytesToBlob(data []byte) dataBlob {
	if len(data) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(data)), pbData: &data[0]}
}

func blobToBytes(blob dataBlob) []byte {
	if blob.cbData == 0 || blob.pbData == nil {
		return nil
	}
	src := unsafe.Slice(blob.pbData, blob.cbData)
	out := make([]byte, len(src))
	copy(out, src)
	return out
}

func localFree(ptr uintptr) {
	if ptr == 0 {
		return
	}
	_, _, _ = procLocalFree.Call(ptr)
}

func protectSecret(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, nil
	}
	in := bytesToBlob(plain)
	var out dataBlob
	r1, _, callErr := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		0,
		0,
		0,
		cryptprotectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	if r1 == 0 {
		return nil, fmt.Errorf("DPAPI protect failed: %w", callErr)
	}
	defer localFree(uintptr(unsafe.Pointer(out.pbData)))
	return blobToBytes(out), nil
}

func unprotectSecret(cipher []byte) ([]byte, error) {
	if len(cipher) == 0 {
		return nil, nil
	}
	in := bytesToBlob(cipher)
	var out dataBlob
	r1, _, callErr := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		0,
		0,
		0,
		cryptprotectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	if r1 == 0 {
		return nil, fmt.Errorf("DPAPI unprotect failed: %w", callErr)
	}
	defer localFree(uintptr(unsafe.Pointer(out.pbData)))
	return blobToBytes(out), nil
}

func secretsStorageDescription() string {
	return "SSH-пароль сохраняется локально и шифруется через Windows DPAPI для текущего пользователя Windows."
}
