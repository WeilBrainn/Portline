package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const mockFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestPortableDigestFailClosed(t *testing.T) {
	if validPlinkDigest([]byte("an untrusted binary")) {
		t.Fatal("must reject untrusted binary")
	}
}

func TestPlinkFingerprintAndPinning(t *testing.T) {
	out := "Host key fingerprint: ssh-ed25519 255 " + mockFingerprint + "\nConnection abandoned."
	if got := fingerprintFromPlink(out); got != mockFingerprint {
		t.Fatalf("got %q", got)
	}
	root := t.TempDir()
	path := filepath.Join(root, "pins.json")
	if err := recordPinnedHost(path, "192.0.2.2:22", mockFingerprint); err != nil {
		t.Fatal(err)
	}
	pins, err := readPinnedHosts(path)
	if err != nil {
		t.Fatal(err)
	}
	if pins["192.0.2.2:22"] != mockFingerprint {
		t.Fatal("pin did not persist")
	}
	other := "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	if err := recordPinnedHost(path, "192.0.2.2:22", other); err == nil {
		t.Fatal("changed host key accepted")
	}
	if got := fingerprintFromPlink("server output without an SSH host key"); got != "" {
		t.Fatal(got)
	}
}

func TestPlinkFallbackMockIntegration(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Unix mock script")
	}
	temp := t.TempDir()
	setTestConfigDir(t, filepath.Join(temp, "config"))
	fake := filepath.Join(temp, "plink")
	script := "#!/bin/sh\n" +
		"case \"$1\" in -v) echo 'Host key fingerprint: ssh-ed25519 255 " + mockFingerprint + "' >&2; exit 1;; esac\n" +
		"cat >/dev/null\n" +
		"printf '::phase|80|Starting service\\n'\n" +
		"printf 'PORTLINE_LINK=vless://mock-key@192.0.2.12:443\\n'\n"
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	a := &App{status: AppStatus{State: "running"}}
	r := requestOK()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.runPlink(ctx, fake, r, "echo test\n"); err != nil {
		t.Fatal(err)
	}
	if a.status.Link != "vless://mock-key@192.0.2.12:443" {
		t.Fatalf("bad link: %s", a.status.Link)
	}
	for _, log := range a.status.Logs {
		if strings.Contains(log, "mock-key") || strings.Contains(log, "test-password") {
			t.Fatal("secret in logs")
		}
	}
	d, _ := appDir()
	pins, _ := readPinnedHosts(filepath.Join(d, "pinned-hosts.json"))
	if pins[hostID(r)] != mockFingerprint {
		t.Fatal("new pin missing")
	}
	matches, err := filepath.Glob(filepath.Join(d, "ssh-password-*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) > 0 {
		t.Fatal("temporary password not removed")
	}
	// Second connection reuses the recorded pin; there is no trust overwrite.
	if err := a.runPlink(ctx, fake, r, "echo test\n"); err != nil {
		t.Fatal(err)
	}
}
