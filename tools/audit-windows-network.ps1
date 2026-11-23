# Read-only audit of Portline's network routes and external IPv4/IPv6.
# This is NOT a kill switch and cannot establish absence of DNS leaks.
param([Parameter(Mandatory=$true)][string]$GatewayIP)
$ErrorActionPreference='Continue'
$parsedIP = $null
if (-not [System.Net.IPAddress]::TryParse($GatewayIP, [ref]$parsedIP)) {
    Write-Host '[ERROR] GatewayIP must be an IP address.'; exit 2
}
Write-Host '--- Portline network audit (read only) ---'
Write-Host ('Gateway: '+$GatewayIP)
$adapter=Get-NetAdapter -Name 'Portline Tunnel' -ErrorAction SilentlyContinue
if ($null -eq $adapter) {Write-Host '[WARN] Portline Tunnel adapter not found.'}
else {
    Write-Host ('Adapter index: '+$adapter.ifIndex+' / '+$adapter.Status)
    foreach($prefix in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')) {
        $routes=Get-NetRoute -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        foreach($r in $routes){Write-Host ('Route '+$prefix+' via index '+$r.InterfaceIndex+' / metric '+$r.RouteMetric)}
    }
    Write-Host 'DNS settings on Portline adapter:'
    Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue | Format-Table -AutoSize
}
Write-Host 'IPv4 egress:'
try {$ip4=(Invoke-RestMethod -Uri 'https://api4.ipify.org' -TimeoutSec 8).Trim();Write-Host ('IPv4: '+$ip4); if($ip4 -ne $GatewayIP){Write-Host '[WARN] External IPv4 differs from the gateway endpoint. Verify VPS NAT and public egress.'}}
catch {Write-Host ('[UNKNOWN] IPv4 egress test failed: '+$_.Exception.Message)}
Write-Host 'IPv6 egress (must NOT bypass the IPv4-only Portline transport):'
try {$ip6=(Invoke-RestMethod -Uri 'https://api6.ipify.org' -TimeoutSec 8).Trim();Write-Host ('[WARNING] Public IPv6 reachable: '+$ip6+' — investigate possible bypass or another IPv6 tunnel.')}
catch {Write-Host '[INFO] Public IPv6 not reachable by this test. This is not proof of leak freedom.'}
Write-Host 'Firewall profile summary:'
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultOutboundAction | Format-Table -AutoSize
Write-Host '[IMPORTANT] Route checks and public IP tests do not replace WFP-based crash-persistent blocking or controlled DNS leak testing.'
