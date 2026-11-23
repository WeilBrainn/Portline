//go:build !windows

package main

func startTray(_ string, _ *App, _ func()) func() {
	return func() {}
}

func notifyExistingInstance() bool {
	return false
}
