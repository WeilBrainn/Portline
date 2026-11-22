package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Test the exact Bash parser embedded in the VPS installer. A Go-only reimplementation
// would not have caught the Xray 26.11.9 label regression.
func TestX25519ParserXrayOutputVariants(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("Bash unavailable; run Bash parser regression tests on Linux/CI")
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
			cmd := exec.Command("bash", "-c", shell, "portline-parser-test", tc.input)
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
