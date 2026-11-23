package main

import (
	"fmt"
	"os"
	"testing"
)

// Never let tests read a live recovery journal or overwrite saved profiles.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "portline-tests-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, key := range []string{"APPDATA", "XDG_CONFIG_HOME"} {
		if err = os.Setenv(key, dir); err != nil {
			os.RemoveAll(dir)
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func setTestConfigDir(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
}
