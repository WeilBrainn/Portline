package main

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Execute the real apply/cleanup scripts; all network mutations are local fakes.
func TestWindowsDNSIPv6AndPartialSetupRollback(t *testing.T) {
	const network = `
$script:routes=@(); $script:addresses=@(); $script:dns=@('8.8.8.8'); $script:mtu=1500; $script:step=0; $script:rules=@([pscustomobject]@{Name='foreign-rule';Protocol='TCP'});
function Check-Step { $script:step++; if($script:step -eq $failAt) {throw 'injected setup failure'} }
function Get-NetAdapter {
 param($Name,[switch]$IncludeHidden,$InterfaceIndex,$ErrorAction)
 if($InterfaceIndex) { return [pscustomobject]@{Name="nic$InterfaceIndex";ifIndex=[int]$InterfaceIndex} }
 [pscustomobject]@{Name='Portline Tunnel';ifIndex=31;InterfaceGuid='{9F1E16A1-AB12-4FC8-B825-BAAD3F6C3C1A}'}
 if(!$Name) { [pscustomobject]@{Name='Ethernet';ifIndex=7}; [pscustomobject]@{Name='Wi-Fi';ifIndex=8} }
}
$script:v6off=@();
function Disable-NetAdapterBinding {
 param([Parameter(ValueFromPipeline=$true)]$InputObject,$ComponentID)
 process { Check-Step; if($ComponentID -ne 'ms_tcpip6') {throw 'wrong binding'}; $script:v6off+=[int]$InputObject.ifIndex }
}
function Enable-NetAdapterBinding {
 param([Parameter(ValueFromPipeline=$true)]$InputObject,$ComponentID)
 process { $script:v6off=@($script:v6off | Where-Object {$_ -ne [int]$InputObject.ifIndex}) }
}
function Get-NetFirewallProfile { [pscustomobject]@{Enabled=($failAt -ne -1);AllowLocalFirewallRules=($failAt -ne -2)} }
function New-NetFirewallRule {
 param($Name,$DisplayName,$Group,$Direction,$Action,$Enabled,$Profile,$Protocol,$RemoteAddress,$RemotePort,$InterfaceAlias,$PolicyStore,$ErrorAction)
 Check-Step
 if($Direction -ne 'Outbound' -or $Action -ne 'Block' -or $Profile -ne 'Any' -or $Enabled -ne 'True') {throw 'unsafe firewall rule'}
 if(($InterfaceAlias -join ',') -ne 'Ethernet,Wi-Fi') {throw 'DNS guard blocks tunnel or misses physical adapter'}
 $script:rules+= [pscustomobject]@{Name=$Name;Protocol=$Protocol;RemoteAddress=$RemoteAddress;RemotePort=$RemotePort}
}
function Get-NetFirewallRule {
 param($Name,$PolicyStore,$ErrorAction)
 $script:rules | Where-Object {!$Name -or $_.Name -eq $Name}
}
function Remove-NetFirewallRule {
 param([Parameter(ValueFromPipeline=$true)]$InputObject)
 process {$script:rules=@($script:rules | Where-Object {$_ -ne $InputObject})}
}
function New-NetRoute {
 param($PolicyStore,$DestinationPrefix,$InterfaceIndex,$NextHop,$RouteMetric,$ErrorAction)
 Check-Step
 $script:routes+= [pscustomobject]@{DestinationPrefix=$DestinationPrefix;InterfaceIndex=$InterfaceIndex;NextHop=$NextHop;RouteMetric=$RouteMetric}
}
function Get-NetRoute {
 param($PolicyStore,$DestinationPrefix,$InterfaceIndex,$AddressFamily,$ErrorAction)
 $script:routes | Where-Object {$_.DestinationPrefix -eq $DestinationPrefix -and $_.InterfaceIndex -eq $InterfaceIndex}
}
function Remove-NetRoute {
 param([Parameter(ValueFromPipeline=$true)]$InputObject,$Confirm)
 process { $script:routes=@($script:routes | Where-Object {$_ -ne $InputObject}) }
}
function New-NetIPAddress {
 param($InterfaceIndex,$IPAddress,$PrefixLength,$AddressFamily,$ErrorAction)
 Check-Step; $script:addresses+= $IPAddress
}
function Get-NetIPAddress {
 param($InterfaceIndex,$IPAddress,$ErrorAction)
 $script:addresses | Where-Object {$_ -eq $IPAddress}
}
function Remove-NetIPAddress {
 param([Parameter(ValueFromPipeline=$true)]$InputObject,$Confirm)
 process {$script:addresses=@($script:addresses | Where-Object {$_ -ne $InputObject})}
}
function Set-NetIPInterface {
 param($InterfaceIndex,$AddressFamily,$NlMtuBytes,$InterfaceMetric,$ErrorAction)
 $script:mtu=$NlMtuBytes
}
function Get-NetIPInterface { [pscustomobject]@{NlMtu=$script:mtu} }
function Set-DnsClientServerAddress {
 param($InterfaceIndex,$ServerAddresses,[switch]$ResetServerAddresses,$ErrorAction)
 if($InterfaceIndex -eq 31) {
  $script:dns=@($ServerAddresses)
 } elseif($InterfaceIndex -eq 7) {
  if($ResetServerAddresses) { $script:physDns=@('192.168.1.1') }
  else { $script:physDns=@($ServerAddresses) }
 } else {
  throw 'unexpected interface DNS change'
 }
}
function Set-DnsClient {}
function Clear-DnsClientCache {}
function Get-DnsClientServerAddress { [pscustomobject]@{ServerAddresses=$script:dns} }
$script:nrpt=@();
function Add-DnsClientNrptRule {
 param($Namespace,$NameServers,$Comment,$ErrorAction)
 $script:nrpt+=[pscustomobject]@{Namespace=$Namespace;NameServers=$NameServers;Comment=$Comment}
}
function Get-DnsClientNrptRule {
 param($ErrorAction)
 $script:nrpt
}
function Remove-DnsClientNrptRule {
 param([Parameter(ValueFromPipeline=$true)]$InputObject,[switch]$Force)
 process { $script:nrpt=@($script:nrpt | Where-Object {$_ -ne $InputObject}) }
}
`
	// Routes-only mode (Windows Firewall disabled): no firewall rules, physical
	// DNS overridden, IPv6 disabled on physical adapters, full rollback.
	for fail := 0; fail <= 8; fail++ {
		t.Run(fmt.Sprintf("routes/%d", fail), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			script := fmt.Sprintf("$failAt=%d; $script:physDns=@('192.168.1.1');\n", fail) + network + `
function Get-NetFirewallProfile { throw 'firewall must not be queried in routes mode' }
function New-NetFirewallRule { throw 'firewall rule created in routes mode' }
try {
` + setRoutesScript + `
if($failAt -ne 0) {throw 'failure injection did not run'}
if(($script:physDns -join ',') -ne '1.1.1.1,9.9.9.9') {throw 'physical DNS was not overridden'}
if(($script:v6off -join ',') -ne '7,8') {throw 'IPv6 not disabled on physical adapters'}
if($script:nrpt.Count -ne 1 -or $script:nrpt[0].Namespace -ne '.') {throw 'NRPT rule not added'}
foreach($prefix in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')) {
 if(!($script:routes | Where-Object {$_.DestinationPrefix -eq $prefix -and $_.InterfaceIndex -eq 31})) {throw 'missing tunnel route'}
}
} catch {
 if($failAt -eq 0 -or $_.Exception.Message -ne 'injected setup failure') {throw}
}
` + cleanupRoutesScript + "\n" + cleanupRoutesScript + `
if($script:routes.Count -ne 0 -or $script:addresses.Count -ne 0) {throw 'rollback left routes or addresses'}
if($script:v6off.Count -ne 0) {throw 'rollback did not re-enable IPv6'}
if(($script:physDns -join ',') -ne '192.168.1.1') {throw 'rollback lost physical adapter DNS'}
if($script:nrpt.Count -ne 0) {throw 'rollback left NRPT rule'}
if(($script:dns -join ',') -ne '8.8.8.8' -or $script:mtu -ne 1500) {throw 'rollback lost DNS or MTU'}
`
			state := testRouteJournal()
			state.Version = 4
			state.EndpointPort = 443
			state.DNSGuardID = "02f3c040-ec93-432f-95e4-47b21b113aad"
			state.GuardMode = "routes"
			state.IPv6Adapters = []int{7, 8}
			state.AdapterDNS = []adapterDNSRecord{{InterfaceIndex: 7}}
			if err := state.validate(); err != nil {
				t.Fatal(err)
			}
			if _, err := runPSOutput(ctx, script, routeEnvironment(state)...); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Test v4 full-tunnel firewall + physical DNS override + rollback.
	for fail := -2; fail <= 11; fail++ {
		t.Run(fmt.Sprintf("v4/%d", fail), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			script := fmt.Sprintf("$failAt=%d; $script:physDns=@('192.168.1.1');\n", fail) + network + "\ntry {\n" + setRoutesScript + `
if($failAt -ne 0) {throw 'failure injection did not run'}
if(($script:dns -join ',') -ne '1.1.1.1,9.9.9.9') {throw 'missing tunnel DNS'}
if(($script:physDns -join ',') -ne '1.1.1.1,9.9.9.9') {throw 'physical DNS was not overridden'}
$guardRules=@($script:rules | Where-Object {$_.Name -ne 'foreign-rule'});
if($guardRules.Count -ne 4) {throw 'missing full-tunnel firewall rules'}
foreach($prefix in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')) {
 if(!($script:routes | Where-Object {$_.DestinationPrefix -eq $prefix -and $_.InterfaceIndex -eq 31})) {throw 'missing tunnel route'}
}
} catch {
 if($failAt -lt 0) {
  if($_.Exception.Message -notlike 'DNS protection requires*' -or $script:step -ne 0) {throw}
 } elseif($failAt -eq 0 -or $_.Exception.Message -ne 'injected setup failure') {throw}
}
` + cleanupRoutesScript + "\n" + cleanupRoutesScript + `
if($script:routes.Count -ne 0 -or $script:addresses.Count -ne 0) {throw 'rollback left routes or addresses'}
if($script:rules.Count -ne 1 -or $script:rules[0].Name -ne 'foreign-rule') {throw 'rollback left DNS blocks or removed foreign rule'}
if(($script:dns -join ',') -ne '8.8.8.8' -or $script:mtu -ne 1500) {throw 'rollback lost DNS or MTU'}
if(($script:physDns -join ',') -ne '192.168.1.1') {throw 'rollback lost physical adapter DNS'}
`
			state := testRouteJournal()
			state.Version = 4
			state.EndpointPort = 8443
			state.DNSGuardID = "02f3c040-ec93-432f-95e4-47b21b113aad"
			state.AdapterDNS = []adapterDNSRecord{{InterfaceIndex: 7, StaticDNS: nil}}
			env := routeEnvironment(state)
			if _, err := runPSOutput(ctx, script, env...); err != nil {
				t.Fatal(err)
			}
		})
	}
}
