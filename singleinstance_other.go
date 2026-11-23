//go:build !windows

package main

import "log"

func acquireAppInstance() (func(), error) { return func() {}, nil }
func notifyStartupFailure(msg string)     { log.Print(msg) }
