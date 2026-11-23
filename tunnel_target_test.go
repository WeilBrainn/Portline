package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"portline/internal/ptunnel"
	"testing"
	"time"
)

func TestTunnelConnectCannotUseDifferentSavedPort(t *testing.T) {
	a := &App{token: "test", lastAccess: time.Now(), status: AppStatus{State: "success", HasNativeProfile: true, NativeProfileHost: "195.123.234.146", NativeProfilePort: 443}, tunnelProfile: ptunnel.Profile{Version: 1, Host: "195.123.234.146", Port: 443}}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/tunnel/connect", bytes.NewBufferString(`{"expectedHost":"195.123.234.146","expectedPort":8449}`))
	req.Header.Set("Authorization", "Bearer test")
	w := httptest.NewRecorder()
	a.serveHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("mismatched port must return conflict, got %d: %s", w.Code, w.Body.String())
	}
	if a.tunnelBusy {
		t.Fatal("mismatched endpoint started a connection")
	}
}
