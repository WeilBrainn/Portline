package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"portline/internal/ptunnel"
)

func TestNativeProvisionOverMockSSH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses shell-based fake SSH")
	}
	dir := t.TempDir()
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	profile := ptunnel.Profile{Version: 1, Host: "203.0.113.14", Port: 8443, Token: token, ServerKeyPin: token}
	secret, err := ptunnel.EncodeProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	ssh := filepath.Join(dir, "ssh.exe")
	script := "#!/bin/sh\ncat > '" + filepath.Join(dir, "received.sh") + "'\nprintf '%s\\n' 'PORTLINE_TUNNEL_PROFILE=" + secret + "'\n"
	if err = os.WriteFile(ssh, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	setTestConfigDir(t, filepath.Join(dir, "config"))
	a := &App{status: AppStatus{State: "running", Protocol: "portline"}}
	input := requestOK()
	input.Protocol = "portline"
	input.Port = 8443
	a.install(input)
	if a.status.State != "success" || !a.status.HasNativeProfile {
		t.Fatalf("expected saved profile, got %+v", a.status)
	}
	if a.tunnelProfile.Host != input.Host {
		t.Fatal("profile mismatch")
	}
	for _, l := range a.status.Logs {
		if strings.Contains(l, secret) || strings.Contains(l, "PORTLINE_TUNNEL_PROFILE=") {
			t.Fatal("credential leaked into logs")
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "received.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "__BINARY_BODY__") {
		t.Fatal("installer binary was not bundled")
	}
	if !strings.Contains(string(data), "sha256sum -c -") {
		t.Fatal("installer lost transfer integrity check")
	}
}
