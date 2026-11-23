package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Test the exact Bash parser embedded in the VPS installer. A Go-only reimplementation
// would not have caught the Xray 26.11.9 label regression.
func TestX25519ParserXrayOutputVariants(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil || !usableBash(bash) {
		t.Skip("Usable Bash unavailable (e.g. WSL without /bin/bash); the installer parser is tested on Linux/CI")
	}
	src, err := os.ReadFile("scripts/vless.sh")
	if err != nil {
		t.Fatal(err)
	}
	code := string(src)
	begin, end := strings.Index(code, "# BEGIN X25519 PARSER"), strings.Index(code, "# END X25519 PARSER")
	if begin < 0 || end <= begin {
		t.Fatal("installer parser block missing")
	}
	parser := code[begin:end]
	key1, key2 := strings.Repeat("A", 43), strings.Repeat("B", 43)
	cases := []struct {
		name, input string
		valid       bool
	}{
		{"old Xray", "Private key: " + key1 + "\nPublic key: " + key2, true},
		{"intermediate Xray", "PrivateKey: " + key1 + "\nPassword: " + key2 + "\nHash32: " + strings.Repeat("C", 43), true},
		{"Xray 26.11.9", "PrivateKey: " + key1 + "\nPassword (PublicKey): " + key2 + "\nHash32: " + strings.Repeat("C", 43), true},
		{"no public key", "PrivateKey: " + key1 + "\nHash32: " + strings.Repeat("C", 43), false},
		{"wrong length", "PrivateKey: abc\nPassword (PublicKey): " + key2, false},
		{"unsupported label", "PrivateKey: " + key1 + "\nPassword (OtherKey): " + key2, false},
		{"malicious suffix", "PrivateKey: " + key1 + "\nPassword (PublicKey): " + key2 + "; echo hacked", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shell := parser + `
if parse_x25519_keys "$1"; then
  printf '%s\n%s\n' "$PRIVATE" "$PUBLIC"
else
  printf 'INVALID\n'
fi
`
			cmd := exec.Command(bash, "-c", shell, "portline-parser-test", tc.input)
			result, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("bash failed: %s: %v", result, err)
			}
			expected := "INVALID\n"
			if tc.valid {
				expected = key1 + "\n" + key2 + "\n"
			}
			if string(result) != expected {
				t.Fatalf("got %q, expected %q", result, expected)
			}
		})
	}
}

// Windows can find bash.exe even when WSL cannot launch /bin/bash.
// The availability probe must reject a command that exists but fails to run.
func TestBashProbeRejectsBrokenExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix shell fixture")
	}
	fake := filepath.Join(t.TempDir(), "bash")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho 'WSL ERROR: /bin/bash not found' >&2\nexit 127\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if usableBash(fake) {
		t.Fatal("broken bash command was treated as available")
	}
}

// Looking up bash.exe is not sufficient on Windows: it may be a WSL launcher
// whose distribution is missing /bin/bash. Probe that a simple script runs.
func usableBash(path string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, path, "-c", "printf 'portline-bash-ready'").CombinedOutput()
	return err == nil && string(output) == "portline-bash-ready"
}
