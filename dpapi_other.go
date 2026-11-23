//go:build !windows

package main

import "errors"

func protectSecret(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, nil
	}
	return nil, errors.New("secure secret storage is only implemented on Windows in this build")
}

func unprotectSecret(cipher []byte) ([]byte, error) {
	if len(cipher) == 0 {
		return nil, nil
	}
	return nil, errors.New("secure secret storage is only implemented on Windows in this build")
}

func secretsStorageDescription() string {
	return "Защищённое сохранение SSH-пароля доступно в Windows-сборке через DPAPI."
}
