package main

import (
	"os"
	"strings"
	"testing"
)

// The gateway is embedded into Portline.exe. Every release build must build
// the gateway from the same commit, not ship the previously committed binary.
func TestWindowsWorkflowBuildsCurrentGateway(t *testing.T) {
	b, err := os.ReadFile(".github/workflows/windows.yml")
	if err != nil {
		t.Fatal(err)
	}
	yml := string(b)
	for _, required := range []string{"cmd/**", "internal/**", "build.ps1", "pwsh -File ./build.ps1"} {
		if !strings.Contains(yml, required) {
			t.Errorf("workflow missing %q", required)
		}
	}
}
