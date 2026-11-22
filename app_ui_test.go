package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInstallerLogStripsTerminalColors(t *testing.T) {
	app := &App{status: AppStatus{State: "running"}}
	app.appendLog("\x1b[31mwarning:\x1b[0m certificate renewed\r")
	if len(app.status.Logs) != 1 || app.status.Logs[0] != "warning: certificate renewed" {
		t.Fatalf("unexpected installer log: %#v", app.status.Logs)
	}
}

func TestIndexUsesBuildVersionAndToken(t *testing.T) {
	app := &App{token: "local-token-123"}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/", nil)
	response := httptest.NewRecorder()
	app.serveHTTP(response, request)
	if response.Code != 200 {
		t.Fatalf("index status: %d", response.Code)
	}
	body := response.Body.String()
	for _, expected := range []string{version, "local-token-123", "data-panel=\"1\"", "data-panel=\"4\""} {
		if !strings.Contains(body, expected) {
			t.Errorf("index is missing %q", expected)
		}
	}
	if strings.Contains(body, "%%VERSION%%") || strings.Contains(body, "%%TOKEN%%") {
		t.Fatal("template placeholders were not replaced")
	}
}

func TestIndexRejectsNonLocalHost(t *testing.T) {
	app := &App{token: "local-token-123"}
	request := httptest.NewRequest(http.MethodGet, "http://example.test:8080/", nil)
	response := httptest.NewRecorder()
	app.serveHTTP(response, request)
	if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), app.token) {
		t.Fatalf("unexpected response for external host: %d %q", response.Code, response.Body.String())
	}
}
