package main

import (
	"strings"
	"testing"
)

func TestDisconnectWithoutSessionDoesNotClaimItRestoredRoutes(t *testing.T) {
	a := &App{}
	a.runTunnelTask("disconnect")
	if a.status.Tunnel.State != "disconnected" {
		t.Fatalf("unexpected state: %+v", a.status.Tunnel)
	}
	if strings.Contains(a.status.Tunnel.Message, "маршруты восстановлены") {
		t.Fatalf("false restoration claim without an active session: %s", a.status.Tunnel.Message)
	}
}
