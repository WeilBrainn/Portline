package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"portline/internal/ptunnel"
	"strings"
	"testing"
)

func TestPortableProfileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	setTestConfigDir(t, dir)
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	profile := ptunnel.Profile{Version: 1, Host: "vpn.example", Port: 443, Token: key, ServerKeyPin: key}
	encoded, err := ptunnel.EncodeProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	app := &App{token: "test-only"}
	request := func(action, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://127.0.0.1/api/tunnel/profile/"+action, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer test-only")
		w := httptest.NewRecorder()
		app.serveHTTP(w, r)
		return w
	}
	if w := request("import", encoded); w.Code != 200 {
		t.Fatal("import status", w.Code)
	}
	if w := request("import", "invalid"); w.Code != 400 {
		t.Fatal("invalid profile status", w.Code)
	}
	restored, ok := restoreTunnelProfile()
	if !ok || restored != profile {
		t.Fatal("saved profile did not round-trip")
	}
	var out struct{ Profile string }
	w := request("export", "")
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != 200 || out.Profile != encoded {
		t.Fatal("export did not round-trip")
	}
	app.nativeSession = &nativeSession{}
	if w := request("import", encoded); w.Code != 409 {
		t.Fatal("replaced connected profile")
	}
}
