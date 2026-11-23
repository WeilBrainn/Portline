package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"portline/internal/ptunnel"
	"runtime"
	"strings"
	"testing"
	"time"
)

func requestOK() InstallRequest {
	return InstallRequest{Host: "203.0.113.14", SSHPort: 22, Username: "root", Password: "test-password", Auth: "password", Protocol: "vless", Port: 443, SNI: "www.cloudflare.com"}
}
func TestValidation(t *testing.T) {
	good := requestOK()
	if err := validate(good); err != nil {
		t.Fatalf("good config rejected: %v", err)
	}
	cases := []struct {
		name   string
		change func(*InstallRequest)
	}{
		{"shell host", func(r *InstallRequest) { r.Host = "1.2.3.4; rm -rf /" }},
		{"wrong ssh", func(r *InstallRequest) { r.SSHPort = 0 }},
		{"bad user", func(r *InstallRequest) { r.Username = "root;reboot" }},
		{"missing password", func(r *InstallRequest) { r.Password = "" }},
		{"wrong transport", func(r *InstallRequest) { r.Protocol = "ftp" }},
		{"bad sni", func(r *InstallRequest) { r.SNI = "www.test.com; reboot" }},
		{"bad port", func(r *InstallRequest) { r.Port = 70000 }},
		{"bad key", func(r *InstallRequest) { r.Auth = "key"; r.KeyFile = "/path/does/not/exist" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := good
			tc.change(&r)
			if validate(r) == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
func TestShellQuote(t *testing.T) {
	v := shellQuote("a'$(reboot)")
	if v != "'a'\\''$(reboot)'" {
		t.Fatal(v)
	}
}
func TestAPIAuthAndValidation(t *testing.T) {
	a := &App{token: "abc123", lastAccess: time.Now(), status: AppStatus{State: "idle"}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://localhost/api/status", nil)
	a.serveHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	r.Header.Set("Authorization", "Bearer abc123")
	w = httptest.NewRecorder()
	a.serveHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	r.Header.Set("Origin", "https://evil.example")
	a.serveHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("origin, got %d", w.Code)
	}
	bad := requestOK()
	bad.Protocol = "invalid"
	data, _ := json.Marshal(bad)
	r = httptest.NewRequest("POST", "http://localhost/api/install", bytes.NewReader(data))
	r.Header.Set("Authorization", "Bearer abc123")
	w = httptest.NewRecorder()
	a.serveHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("invalid request got %d", w.Code)
	}
}
func TestInstallWithMockSSH(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("mock shell requires Unix")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "ssh.exe")
	script := "#!/bin/sh\ncat > '" + filepath.Join(dir, "script.txt") + "'\nprintf '::phase|65|Конфигурация\\n'\nprintf 'PORTLINE_LINK=vless://test-secret@127.0.0.1:443\\n'\nprintf 'Service is active\\n'\n"
	if err := os.WriteFile(p, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	setTestConfigDir(t, filepath.Join(dir, "config"))
	a := &App{token: "hi", status: AppStatus{State: "running"}}
	a.install(requestOK())
	if a.status.State != "success" {
		t.Fatalf("status: %+v", a.status)
	}
	if a.status.Link != "vless://test-secret@127.0.0.1:443" {
		t.Fatal(a.status.Link)
	}
	for _, l := range a.status.Logs {
		if strings.Contains(l, "test-secret") {
			t.Fatal("secret leaked into logs")
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "script.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("export NP_ADDR='203.0.113.14'")) {
		t.Fatal("server address not embedded")
	}
	if !bytes.Contains(b, []byte("xray x25519")) {
		t.Fatal("wrong embedded installer")
	}
}

func TestHAPPInstallReturnsImmediatelyAndReportsStatus(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Do not execute a real installer in a Windows unit test")
	}
	a := &App{token: "test", status: AppStatus{State: "success", Link: "vless://test@127.0.0.1"}}
	req := httptest.NewRequest("POST", "http://127.0.0.1/api/happ-install", nil)
	req.Header.Set("Authorization", "Bearer test")
	w := httptest.NewRecorder()
	a.serveHTTP(w, req)
	if w.Code != 202 {
		t.Fatalf("expected accepted, got %d: %s", w.Code, w.Body.String())
	}
	deadline := time.Now().Add(time.Second)
	for {
		a.mu.Lock()
		state := a.status.HAPP.State
		message := a.status.HAPP.Message
		a.mu.Unlock()
		if state == "error" {
			if message == "" {
				t.Fatal("failure must describe the recovery path")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("task stuck: %s", state)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestQuitDoesNotInterruptHAPP(t *testing.T) {
	a := &App{token: "test", happBusy: true, status: AppStatus{State: "success"}}
	req := httptest.NewRequest("POST", "http://127.0.0.1/api/quit", nil)
	req.Header.Set("Authorization", "Bearer test")
	w := httptest.NewRecorder()
	a.serveHTTP(w, req)
	if w.Code != 409 {
		t.Fatalf("expected 409, got %d", w.Code)
	}
}

// A browser using DNS rebinding must not be able to read the API bearer token
// from the root HTML page, even when the listener is bound to 127.0.0.1.
func TestRejectNonLocalHostHeader(t *testing.T) {
	a := &App{token: "very-private-token", lastAccess: time.Now()}
	for _, host := range []string{"portline.attacker.example", "portline.attacker.example:4242", "127.0.0.1.attacker.example:4242", "[::1]:4242"} {
		t.Run(host, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://127.0.0.1:4242/", nil)
			r.Host = host
			w := httptest.NewRecorder()
			a.serveHTTP(w, r)
			if w.Code != 403 {
				t.Fatalf("host %q returned HTTP %d", host, w.Code)
			}
			if strings.Contains(w.Body.String(), a.token) {
				t.Fatalf("bearer token disclosed to host %q", host)
			}
		})
	}
	for _, host := range []string{"127.0.0.1:4242", "localhost:4242"} {
		r := httptest.NewRequest("GET", "http://127.0.0.1:4242/", nil)
		r.Host = host
		w := httptest.NewRecorder()
		a.serveHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), a.token) {
			t.Fatalf("expected local UI for %s, status %d", host, w.Code)
		}
	}
}

func TestConnectingTwiceCannotReplaceActiveTunnel(t *testing.T) {
	a := &App{
		token: "test", lastAccess: time.Now(),
		status:        AppStatus{State: "success", HasNativeProfile: true},
		nativeSession: &nativeSession{done: make(chan struct{})},
	}
	req := httptest.NewRequest("POST", "http://127.0.0.1:4242/api/tunnel/connect", nil)
	req.Header.Set("Authorization", "Bearer test")
	w := httptest.NewRecorder()
	a.serveHTTP(w, req)
	if w.Code != 409 {
		t.Fatalf("expected conflict for active tunnel, got %d", w.Code)
	}
	if a.tunnelBusy {
		t.Fatal("existing connection replaced")
	}
}

func TestPortlineInstallRequiresFreshProfile(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("mock shell requires Unix")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "ssh.exe")
	script := "#!/bin/sh\nprintf '::phase|65|Конфигурация\n'\nprintf 'Service is active\n'\n"
	if err := os.WriteFile(p, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	setTestConfigDir(t, filepath.Join(dir, "config"))
	a := &App{token: "hi", status: AppStatus{State: "running", HasNativeProfile: true, NativeProfileHost: "203.0.113.14", NativeProfilePort: 443}, tunnelProfile: ptunnel.Profile{Version: 1, Host: "203.0.113.14", Port: 443, ServerKeyPin: strings.Repeat("A", 43), Token: strings.Repeat("A", 43)}}
	r := requestOK()
	r.Protocol = "portline"
	r.Port = 8449
	a.install(r)
	if a.status.State != "error" {
		t.Fatalf("expected error, got %+v", a.status)
	}
	if !strings.Contains(a.status.Error, "не вернул новый профиль") {
		t.Fatalf("unexpected error: %s", a.status.Error)
	}
}

func TestProfilesAPI(t *testing.T) {
	dir := t.TempDir()
	setTestConfigDir(t, dir)
	a := &App{token: "abc123", lastAccess: time.Now(), status: AppStatus{State: "idle"}}
	body := bytes.NewBufferString(`{"name":"test","host":"203.0.113.10","sshPort":22,"username":"root","auth":"password","protocol":"portline","port":8443}`)
	r := httptest.NewRequest("POST", "http://localhost/api/profiles", body)
	r.Header.Set("Authorization", "Bearer abc123")
	w := httptest.NewRecorder()
	a.serveHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("save profile got %d: %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest("GET", "http://localhost/api/profiles", nil)
	r.Header.Set("Authorization", "Bearer abc123")
	w = httptest.NewRecorder()
	a.serveHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "203.0.113.10") {
		t.Fatalf("list profiles failed: %d %s", w.Code, w.Body.String())
	}
}
