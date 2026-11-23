package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Exercise the production PowerShell with simulated CIM objects. Every
// network command is replaced, so the test requires no adapter or elevation.
func TestWindowsRouteRecoveryPreservesMTU(t *testing.T) {
	const mockNetwork = `
function Get-NetAdapter { [pscustomobject]@{ifIndex=31;InterfaceGuid='{9F1E16A1-AB12-4FC8-B825-BAAD3F6C3C1A}'} }
function Get-NetRoute {
 param($AddressFamily,$PolicyStore,$DestinationPrefix,$InterfaceIndex,$ErrorAction)
 if ($DestinationPrefix -eq '0.0.0.0/0') {
  [pscustomobject]@{InterfaceIndex=7;NextHop='192.168.1.1';RouteMetric=10}
 }
}
function Get-NetIPAddress {}
function Get-ItemProperty {}
function Get-NetIPInterface { [pscustomobject]@{NlMtu=$mtu} }
function Get-DnsClientServerAddress {}
function Remove-NetRoute {}
function Remove-NetIPAddress {}
function Set-DnsClientServerAddress { throw 'Unexpected DNS update' }
function Set-NetIPInterface {
 param($InterfaceIndex,$AddressFamily,$NlMtuBytes,$ErrorAction)
 'restored:' + $InterfaceIndex + ':' + $NlMtuBytes
}
`
	t.Run("snapshot", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		raw, err := runPSOutput(ctx, mockNetwork+"\n$mtu=65535;\n"+inspectRoutesScript, "PORTLINE_SERVER_IPV4=203.0.113.18")
		if err != nil {
			t.Fatal(err)
		}
		var saved routeJournal
		if err := json.Unmarshal(raw, &saved); err != nil {
			t.Fatal(err)
		}
		if err := saved.validate(); err != nil {
			t.Fatalf("journal validation failed with MTU %d: %v", saved.PreviousMTU, err)
		}
		if saved.PreviousMTU != 65535 {
			t.Fatalf("saved MTU = %d, want 65535", saved.PreviousMTU)
		}
	})
	t.Run("rollback", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		raw, err := runPSOutput(ctx, mockNetwork+"\n$mtu=1280;\n"+cleanupRoutesScript, routeEnvironment(testRouteJournal())...)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(raw)); got != "restored:31:1500" {
			t.Fatalf("rollback output = %q, want restored:31:1500", got)
		}
	})
}
