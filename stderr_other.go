//go:build !windows

package main

import "os"

func redirectStderr(_ *os.File) {}
