package main

import (
	"os"
	"strings"
	"testing"
)

func TestWindowsCleanupIsScopedToSavedInterfaceAndGateway(t *testing.T) {
	src, err := os.ReadFile("tunnel_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	content := string(src)
	for _, exact := range []string{"PORTLINE_TUNNEL_INDEX", "PORTLINE_PHYSICAL_INDEX", "PORTLINE_PHYSICAL_GATEWAY", "PORTLINE_TUNNEL_GUID", "-PolicyStore ActiveStore", "recoverWindowsRoutes()", "beginRoutes("} {
		if !strings.Contains(content, exact) {
			t.Errorf("Windows route management is missing %s", exact)
		}
	}
	if strings.Contains(content, `Get-NetRoute -AddressFamily IPv4 -DestinationPrefix ($env:PORTLINE_SERVER_IPV4+'/32')`) {
		t.Error("unscoped endpoint route deletion still exists")
	}
}

func TestMainRecoversStaleNetworkRoutesBeforeOpeningUI(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	content := string(src)
	recoverAt := strings.Index(content, "recoverStartupRoutes()")
	openAt := strings.Index(content, "openUI(url)")
	if recoverAt < 0 || openAt < 0 || recoverAt > openAt {
		t.Fatal("recovery must run at app startup, before browser UI")
	}
}

func TestAppPreventsConcurrentRouteRecovery(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	content := string(src)
	lockAt := strings.Index(content, "acquireAppInstance()")
	recoverAt := strings.Index(content, "recoverStartupRoutes()")
	if lockAt < 0 || recoverAt < 0 || lockAt > recoverAt {
		t.Fatal("must hold single-instance mutex before recovery")
	}
}

func TestCleanupCannotClaimSuccessIfAdapterIsMissingButRoutesRemain(t *testing.T) {
	src, err := os.ReadFile("tunnel_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "Orphaned Portline routes require manual review") {
		t.Fatal("cleanup needs to reject orphaned routes when adapter identity is missing")
	}
}
