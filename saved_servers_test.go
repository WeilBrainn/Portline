package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSavedServersRoundTrip(t *testing.T) {
	dir := t.TempDir()
	setTestConfigDir(t, dir)
	app := &App{}
	one, err := app.saveServerProfile(saveProfileRequest{Host: "203.0.113.10", SSHPort: 22, Username: "root", Auth: "password", Protocol: "portline", Port: 8443})
	if err != nil {
		t.Fatal(err)
	}
	if one.ID == "" || one.Name == "" {
		t.Fatalf("profile not populated: %+v", one)
	}
	second, err := app.saveServerProfile(saveProfileRequest{Host: "198.51.100.5", SSHPort: 2222, Username: "admin", Auth: "key", KeyFile: "/tmp/key", Protocol: "vless", Port: 443, SNI: "www.cloudflare.com", Name: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if len(app.listServerProfiles()) != 2 {
		t.Fatalf("want 2 profiles, got %d", len(app.listServerProfiles()))
	}
	loaded, err := loadSavedServers()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 2 {
		t.Fatalf("want 2 loaded profiles, got %d", len(loaded))
	}
	if loaded[0].Name != "prod" && loaded[1].Name != "prod" {
		t.Fatalf("saved profile missing: %+v", loaded)
	}
	if err = app.deleteServerProfile(second.ID); err != nil {
		t.Fatal(err)
	}
	if len(app.listServerProfiles()) != 1 {
		t.Fatalf("want 1 profile after delete, got %d", len(app.listServerProfiles()))
	}
	path, _ := savedServersPath()
	if _, err = os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) == dir {
		t.Fatal("profile path should be nested under Portline")
	}
}

func TestSaveProfileValidation(t *testing.T) {
	app := &App{}
	if _, err := app.saveServerProfile(saveProfileRequest{Host: "bad host", SSHPort: 22, Username: "root", Auth: "password", Protocol: "portline", Port: 8443}); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadProfileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	setTestConfigDir(t, dir)
	app := &App{}
	profile, err := app.saveServerProfile(saveProfileRequest{Host: "203.0.113.99", SSHPort: 22, Username: "root", Auth: "key", KeyFile: "/tmp/key", Protocol: "portline", Port: 8443, Name: "node"})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := app.loadServerProfile(profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Host != "203.0.113.99" || loaded.Name != "node" || loaded.Password != "" {
		t.Fatalf("unexpected loaded profile: %+v", loaded)
	}
}
