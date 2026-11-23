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

func TestGatewayInspectionDoesNotReinstall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake SSH uses POSIX shell")
	}
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh.exe")
	script := "#!/bin/sh\ncat >'" + filepath.Join(dir, "remote-script") + "'\nprintf 'PORTLINE_GATEWAY|installed|active|8449|legacy|1|203.0.113.20\\n'\n"
	if err := os.WriteFile(ssh, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	setTestConfigDir(t, filepath.Join(dir, "settings"))
	a := &App{}
	r := requestOK()
	r.Host = "203.0.113.20"
	r.Port = 8449
	r.Protocol = "portline"
	a.runGatewayAction(r, "inspect")
	if a.status.GatewayAction != "success" || !a.status.Gateway.Compatible || a.status.Gateway.Port != "8449" {
		t.Fatalf("gateway report: %+v", a.status)
	}
	content, err := os.ReadFile(filepath.Join(dir, "remote-script"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "__BINARY_BODY__") {
		t.Fatal("inspection must not upload gateway executable")
	}
}

func TestGatewayUseImportsExistingCredentials(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake SSH uses POSIX shell")
	}
	dir := t.TempDir()
	dummy := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	p := ptunnel.Profile{Version: 1, Host: "203.0.113.20", Port: 8449, Token: dummy, ServerKeyPin: dummy}
	encoded, err := ptunnel.EncodeProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	ssh := filepath.Join(dir, "ssh.exe")
	script := "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' 'PORTLINE_TUNNEL_PROFILE=" + encoded + "'\n"
	if err = os.WriteFile(ssh, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	setTestConfigDir(t, filepath.Join(dir, "settings"))
	a := &App{status: AppStatus{Gateway: GatewayInspection{State: "installed", Activity: "active", Port: "8449", Host: p.Host, Compatible: true}}}
	r := requestOK()
	r.Host = p.Host
	r.Port = 8449
	r.Protocol = "portline"
	a.runGatewayAction(r, "use")
	if a.status.GatewayAction != "success" || !a.status.HasNativeProfile || a.tunnelProfile.Port != 8449 {
		t.Fatalf("cannot import existing Gateway: %+v", a.status)
	}
	for _, line := range a.status.Logs {
		if strings.Contains(line, encoded) {
			t.Fatal("secret printed in logs")
		}
	}
}
