# Read-only Portline troubleshooting tool. Never removes or modifies routes.
$ErrorActionPreference = 'Continue'
Write-Host 'Portline - active routes that can conflict with a full tunnel'
Write-Host '(read-only check; no network settings will be changed)'
$prefixes = @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')
$found = $false
foreach ($prefix in $prefixes) {
  $routes = @(Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix $prefix -ErrorAction SilentlyContinue)
  foreach ($route in $routes) {
    if ($null -eq $route) { continue }
    $found = $true
    $index = [int]$route.InterfaceIndex
    $adapter = Get-NetAdapter -InterfaceIndex $index -ErrorAction SilentlyContinue
    $name = if ($adapter) { $adapter.Name } else { $route.InterfaceAlias }
    Write-Host ("{0}  Interface #{1} ({2})  NextHop={3}  Metric={4}" -f $prefix,$index,$name,$route.NextHop,$route.RouteMetric)
  }
}
if (-not $found) {
  Write-Host 'No split-default (/1) routes were found.'
} else {
  Write-Host 'If another VPN is running, disconnect it through its application.'
  Write-Host 'Do not remove these routes manually without identifying the owner.'
}
Write-Host 'Portline adapter (if present):'
Get-NetAdapter -Name 'Portline Tunnel' -ErrorAction SilentlyContinue |
  Select-Object Name, InterfaceIndex, Status, InterfaceDescription | Format-Table -AutoSize
