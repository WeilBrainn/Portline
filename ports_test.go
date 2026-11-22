package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPortReportsAndSuggestions(t *testing.T) {
	p := PortTask{State: "running"}
	if err := applyPortReport(&p, "PORTLINE_PORT|busy|tcp|443|xray.service|xray|577|1"); err != nil {
		t.Fatal(err)
	}
	if p.State != "busy" || p.Service != "xray.service" || !p.CanStop || p.Port != 443 || p.PID != 577 {
		t.Fatalf("%+v", p)
	}
	if err := applyPortReport(&p, "PORTLINE_PORT|stopped|tcp|443|xray.service|xray|577|0"); err != nil {
		t.Fatal(err)
	}
	if p.State != "stopped" || p.CanStop {
		t.Fatalf("%+v", p)
	}
	if err := applyPortReport(&p, "PORTLINE_PORT|free|udp|8443|-|-|-|0"); err != nil {
		t.Fatal(err)
	}
	if p.State != "free" || p.Process != "" || p.Port != 8443 {
		t.Fatalf("%+v", p)
	}
	if err := applyPortReport(&p, "PORTLINE_PORT|bad|tcp|443|xray.service|xray|577|1"); err == nil {
		t.Fatal("unexpected status accepted")
	}
	got := parsePortSuggestions("8443,2053,2053,invalid,0,2083,65432")
	if len(got) != 3 || got[0] != 8443 || got[1] != 2053 || got[2] != 2083 {
		t.Fatalf("%v", got)
	}
}

func TestPortStopRequiresFreshAuthorizedCheck(t *testing.T) {
	a := &App{token: "test", status: AppStatus{State: "idle"}}
	payload, _ := json.Marshal(PortStopRequest{InstallRequest: requestOK(), Service: "xray.service"})
	r := httptest.NewRequest("POST", "http://127.0.0.1/api/ports/stop", bytes.NewReader(payload))
	r.Header.Set("Authorization", "Bearer test")
	w := httptest.NewRecorder()
	a.serveHTTP(w, r)
	if w.Code != 409 {
		t.Fatalf("stop without inspection returned %d", w.Code)
	}
	a.portKey = portIdentity(requestOK())
	a.status.PortTask = PortTask{State: "busy", Port: 443, Protocol: "tcp", Service: "xray.service", CanStop: true}
	swapped := requestOK()
	swapped.Port = 8443
	payload, _ = json.Marshal(PortStopRequest{InstallRequest: swapped, Service: "xray.service"})
	r = httptest.NewRequest("POST", "http://127.0.0.1/api/ports/stop", bytes.NewReader(payload))
	r.Header.Set("Authorization", "Bearer test")
	w = httptest.NewRecorder()
	a.serveHTTP(w, r)
	if w.Code != 409 {
		t.Fatalf("stale port accepted: %d", w.Code)
	}
	payload, _ = json.Marshal(PortStopRequest{InstallRequest: requestOK(), Service: "sshd.service"})
	r = httptest.NewRequest("POST", "http://127.0.0.1/api/ports/stop", bytes.NewReader(payload))
	r.Header.Set("Authorization", "Bearer test")
	w = httptest.NewRecorder()
	a.serveHTTP(w, r)
	if w.Code != 409 {
		t.Fatalf("wrong unit accepted: %d", w.Code)
	}
}

func TestPortInspectionAndStopViaMockSSH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mock shell requires Unix")
	}
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh.exe")
	script := `#!/bin/sh
payload="$(cat)"
if printf '%s' "$payload" | grep -q "NP_CTL_ACTION='stop'";then
  printf 'PORTLINE_PORT|stopped|tcp|443|xray.service|xray|577|0\n'
else
  printf 'PORTLINE_PORT|busy|tcp|443|xray.service|xray|577|1\n'
  printf 'PORTLINE_SUGGEST|8443,2053,2083\n'
fi
`
	if err := os.WriteFile(ssh, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	a := &App{token: "test", status: AppStatus{State: "idle", Logs: []string{}}}
	send := func(endpoint string, body any) int {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "http://127.0.0.1"+endpoint, bytes.NewReader(b))
		r.Header.Set("Authorization", "Bearer test")
		w := httptest.NewRecorder()
		a.serveHTTP(w, r)
		return w.Code
	}
	if code := send("/api/ports/check", requestOK()); code != 202 {
		t.Fatalf("check code %d", code)
	}
	wait := func(state string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			a.mu.Lock()
			s := a.status.PortTask
			b := a.portBusy
			a.mu.Unlock()
			if s.State == state && !b {
				return
			}
			if s.State == "error" {
				t.Fatalf("port error: %s", s.Message)
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("timeout waiting for %s", state)
	}
	wait("busy")
	a.mu.Lock()
	port := a.status.PortTask
	a.mu.Unlock()
	if !port.CanStop || port.Service != "xray.service" || len(port.Suggestions) != 3 {
		t.Fatalf("%+v", port)
	}
	if code := send("/api/ports/stop", PortStopRequest{InstallRequest: requestOK(), Service: "xray.service"}); code != 202 {
		t.Fatalf("stop code %d", code)
	}
	wait("stopped")
	a.mu.Lock()
	logs := strings.Join(a.status.Logs, "\n")
	a.mu.Unlock()
	if strings.Contains(logs, "test-password") {
		t.Fatal("credential leaked into logs")
	}
}
