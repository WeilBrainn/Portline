package main

import (
	"context"
	"os/exec"
)

// backgroundCommand keeps every maintenance subprocess out of the user's
// desktop while still streaming its output to the in-app progress UI.
func backgroundCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	hideConsole(cmd)
	return cmd
}
