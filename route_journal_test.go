package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testRouteJournal() routeJournal {
	return routeJournal{Version: 1, Endpoint: "203.0.113.18", TunnelInterface: 31, TunnelGUID: "{9F1E16A1-AB12-4FC8-B825-BAAD3F6C3C1A}", PhysicalInterface: 7, PhysicalGateway: "192.168.1.1", PreviousMTU: 1500, StaticDNS: []string{"8.8.8.8"}}
}

func TestRouteJournalPersistsBeforeApplyingRoutes(t *testing.T) {
	file := filepath.Join(t.TempDir(), "network.json")
	state := testRouteJournal()
	if err := beginRoutes(file, state, func(got routeJournal) error {
		if got.Endpoint != state.Endpoint {
			t.Fatalf("incorrect journal before applying: %+v", got)
		}
		if _, err := os.Stat(file); err != nil {
			t.Fatalf("state must be durable before modifying routes: %v", err)
		}
		return nil
	}, func(routeJournal) error { t.Fatal("unnecessary cleanup"); return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("journal missing while connected:", err)
	}
}

func TestRouteRecoveryRestoresAfterSimulatedCrash(t *testing.T) {
	file := filepath.Join(t.TempDir(), "network.json")
	state := testRouteJournal()
	if err := beginRoutes(file, state, func(routeJournal) error { return nil }, func(routeJournal) error { return nil }); err != nil {
		t.Fatal(err)
	}
	// A second process is not aware of the original session; only the journal survives.
	called := 0
	if err := recoverRoutes(file, func(got routeJournal) error {
		called++
		if got.Endpoint != state.Endpoint || got.TunnelInterface != state.TunnelInterface || got.PhysicalGateway != state.PhysicalGateway {
			t.Fatalf("restored wrong network state: %+v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("expected one recovery, got %d", called)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery marker must be removed after success: %v", err)
	}
}

func TestRouteRecoveryFailureRetainsJournal(t *testing.T) {
	file := filepath.Join(t.TempDir(), "network.json")
	if err := beginRoutes(file, testRouteJournal(), func(routeJournal) error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	if err := recoverRoutes(file, func(routeJournal) error { return errors.New("powershell failed") }); err == nil {
		t.Fatal("expected cleanup failure")
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("must retain journal for retry:", err)
	}
}

func TestRouteSetupFailureAttemptsRollback(t *testing.T) {
	file := filepath.Join(t.TempDir(), "network.json")
	rollbacks := 0
	err := beginRoutes(file, testRouteJournal(), func(routeJournal) error { return errors.New("half-default route rejected") }, func(routeJournal) error { rollbacks++; return nil })
	if err == nil || !strings.Contains(err.Error(), "half-default route rejected") {
		t.Fatalf("lost original error: %v", err)
	}
	if rollbacks != 1 {
		t.Fatalf("expected rollback, got %d", rollbacks)
	}
	if _, err = os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful rollback left journal")
	}
}

func TestRouteJournalRejectsInvalidOrPreexistingChanges(t *testing.T) {
	file := filepath.Join(t.TempDir(), "network.json")
	invalid := testRouteJournal()
	invalid.Endpoint = "&& Start-Process powershell"
	if err := beginRoutes(file, invalid, func(routeJournal) error { t.Fatal("invalid input applied"); return nil }, nil); err == nil {
		t.Fatal("invalid endpoint accepted")
	}
	if err := beginRoutes(file, testRouteJournal(), func(routeJournal) error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	if err := beginRoutes(file, testRouteJournal(), func(routeJournal) error { t.Fatal("should not modify system while prior journal exists"); return nil }, nil); err == nil {
		t.Fatal("overwrote active journal")
	}
	if err := os.WriteFile(file, []byte("{truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := recoverRoutes(file, func(routeJournal) error { t.Fatal("corrupt state must not invoke shell"); return nil }); err == nil {
		t.Fatal("corrupt journal ignored")
	}
}

func TestRecoveryJournalDynamicAddress(t *testing.T) {
	state := testRouteJournal()
	state.Version = 2
	state.ClientIP = "10.76.24.4"
	path := filepath.Join(t.TempDir(), "network.json")
	if err := storeRouteJournal(path, state); err != nil {
		t.Fatal(err)
	}
	got, exists, err := readRouteJournal(path)
	if err != nil || !exists || got.ClientIP != state.ClientIP {
		t.Fatal("lost assigned tunnel address", err)
	}
	for _, ip := range []string{"", "192.168.1.2", "10.76.24.1", "10.76.24.255"} {
		state.ClientIP = ip
		if state.validate() == nil {
			t.Fatal("unsafe recovery address", ip)
		}
	}
}
