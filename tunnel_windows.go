//go:build windows

package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"portline/internal/ptunnel"
)

const wintunURL = "https://www.wintun.net/builds/wintun-0.14.1.zip"
const wintunZipSHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"

// Wintun is a generic signed Layer-3 Windows adapter, not a VPN engine.
func ensureWintun(ctx context.Context, report func(string)) (string, error) {
	dir, err := appDir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, "drivers")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	dllPath := filepath.Join(dir, "wintun.dll")
	if st, err := os.Stat(dllPath); err == nil && st.Size() > 10000 {
		// A cached DLL can be tampered with. Refuse to use it if its signed
		// publisher certificate cannot be verified by the Windows trust store.
		if err := verifyWintunSignature(ctx, dllPath); err == nil {
			return dllPath, nil
		}
		_ = os.Remove(dllPath)
	}
	report("Загружаем подписанный сетевой адаптер Wintun")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wintunURL, nil)
	if err != nil {
		return "", err
	}
	response, err := (&http.Client{Timeout: time.Minute}).Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Wintun download: HTTP %d", response.StatusCode)
	}
	file, err := os.CreateTemp(dir, "wintun-*.zip")
	if err != nil {
		return "", err
	}
	temp := file.Name()
	defer os.Remove(temp)
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(file, h), io.LimitReader(response.Body, 20<<20))
	closeErr := file.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	if n >= 20<<20 || hex.EncodeToString(h.Sum(nil)) != wintunZipSHA256 {
		return "", errors.New("контрольная сумма архива Wintun не совпала")
	}
	archive, err := zip.OpenReader(temp)
	if err != nil {
		return "", err
	}
	defer archive.Close()
	for _, entry := range archive.File {
		if entry.Name != "wintun/bin/amd64/wintun.dll" {
			continue
		}
		stream, err := entry.Open()
		if err != nil {
			return "", err
		}
		dest := dllPath + ".partial"
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			stream.Close()
			return "", err
		}
		bytesCopied, copyErr := io.Copy(out, io.LimitReader(stream, 2<<20))
		stream.Close()
		out.Close()
		if copyErr != nil || bytesCopied < 10000 || bytesCopied >= 2<<20 {
			os.Remove(dest)
			return "", errors.New("неверный файл Wintun")
		}
		if err = verifyWintunSignature(ctx, dest); err != nil {
			_ = os.Remove(dest)
			return "", err
		}
		if err = os.Rename(dest, dllPath); err != nil {
			return "", err
		}
		return dllPath, nil
	}
	return "", errors.New("в архиве отсутствует Wintun для x64")
}

// Verify the signed DLL as well as the pinned ZIP digest. Never load a
// substituted binary into Portline's elevated process.
func verifyWintunSignature(ctx context.Context, file string) error {
	script := `$ErrorActionPreference='Stop'; $sig=Get-AuthenticodeSignature -LiteralPath $env:PORTLINE_WINTUN_DLL; if ($sig.Status -ne 'Valid' -or !$sig.SignerCertificate) { throw 'Wintun signature is invalid' }`
	return runPS(ctx, script, "PORTLINE_WINTUN_DLL="+file)
}

type wintunProc interface {
	Call(...uintptr) (uintptr, uintptr, error)
}

var procWaitForSingleObject = syscall.NewLazyDLL("kernel32.dll").NewProc("WaitForSingleObject")

type wintunDevice struct {
	dll          *syscall.DLL
	adapter      uintptr
	session      uintptr
	readEvent    uintptr
	closeOnce    sync.Once
	receive      wintunProc
	release      *syscall.Proc
	allocate     wintunProc
	send         *syscall.Proc
	endSession   *syscall.Proc
	closeAdapter *syscall.Proc
}

func (d *wintunDevice) Close() {
	d.closeOnce.Do(func() {
		if d.session != 0 {
			d.endSession.Call(d.session)
		}
		if d.adapter != 0 {
			d.closeAdapter.Call(d.adapter)
		}
		if d.dll != nil {
			d.dll.Release()
		}
	})
}
func newWintun(path string) (*wintunDevice, error) {
	dll, err := syscall.LoadDLL(path)
	if err != nil {
		return nil, err
	}
	p := func(n string) (*syscall.Proc, error) { return dll.FindProc(n) }
	open, err := p("WintunOpenAdapter")
	if err != nil {
		dll.Release()
		return nil, err
	}
	create, err := p("WintunCreateAdapter")
	if err != nil {
		dll.Release()
		return nil, err
	}
	closeAdapter, err := p("WintunCloseAdapter")
	if err != nil {
		dll.Release()
		return nil, err
	}
	start, err := p("WintunStartSession")
	if err != nil {
		dll.Release()
		return nil, err
	}
	end, err := p("WintunEndSession")
	if err != nil {
		dll.Release()
		return nil, err
	}
	receive, err := p("WintunReceivePacket")
	if err != nil {
		dll.Release()
		return nil, err
	}
	release, err := p("WintunReleaseReceivePacket")
	if err != nil {
		dll.Release()
		return nil, err
	}
	allocate, err := p("WintunAllocateSendPacket")
	if err != nil {
		dll.Release()
		return nil, err
	}
	send, err := p("WintunSendPacket")
	if err != nil {
		dll.Release()
		return nil, err
	}
	getReadEvent, err := p("WintunGetReadWaitEvent")
	if err != nil {
		dll.Release()
		return nil, err
	}
	name, err := syscall.UTF16PtrFromString(ptunnel.TunnelAlias)
	if err != nil {
		dll.Release()
		return nil, err
	}
	adapter, _, _ := open.Call(uintptr(unsafe.Pointer(name)))
	if adapter == 0 {
		tunnelType, _ := syscall.UTF16PtrFromString("Portline")
		adapter, _, err = create.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(tunnelType)), 0)
		if adapter == 0 {
			dll.Release()
			return nil, fmt.Errorf("WintunCreateAdapter: %w", err)
		}
	}
	session, _, err := start.Call(adapter, 0x400000)
	if session == 0 {
		closeAdapter.Call(adapter)
		dll.Release()
		return nil, fmt.Errorf("WintunStartSession: %w", err)
	}
	readEvent, _, _ := getReadEvent.Call(session)
	return &wintunDevice{dll: dll, adapter: adapter, session: session, readEvent: readEvent, receive: receive, release: release, allocate: allocate, send: send, endSession: end, closeAdapter: closeAdapter}, nil
}
func (d *wintunDevice) ReadPacket(ctx context.Context) ([]byte, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		var size uint32
		ptr, _, err := d.receive.Call(d.session, uintptr(unsafe.Pointer(&size)))
		if ptr == 0 {
			if !errors.Is(err, syscall.Errno(259)) { // ERROR_NO_MORE_ITEMS: the receive queue is empty.
				return nil, fmt.Errorf("WintunReceivePacket: %w", err)
			}
			if d.readEvent != 0 {
				_, _, _ = procWaitForSingleObject.Call(d.readEvent, 100)
			} else {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(5 * time.Millisecond):
				}
			}
			continue
		}
		if size > uint32(ptunnel.MTU) {
			d.release.Call(d.session, ptr)
			continue
		}
		bytes := append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(ptr)), int(size))...)
		d.release.Call(d.session, ptr)
		return bytes, nil
	}
}
func (d *wintunDevice) WritePacket(p []byte) error {
	if len(p) == 0 || len(p) > ptunnel.MTU {
		return errors.New("invalid packet size")
	}
	ptr, _, err := d.allocate.Call(d.session, uintptr(len(p)))
	if ptr == 0 {
		if errors.Is(err, syscall.Errno(111)) { // ERROR_BUFFER_OVERFLOW: drop this packet, keep the tunnel alive.
			return nil
		}
		return fmt.Errorf("WintunAllocateSendPacket: %w", err)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(ptr)), len(p)), p)
	d.send.Call(d.session, ptr)
	return nil
}

func runPS(ctx context.Context, script string, env ...string) error {
	cmd := backgroundCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), env...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("network configuration failed: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// A startup recovery record is saved BEFORE any network modification. Routes
// are restricted to the recorded interface and endpoint; never delete by prefix
// alone because the PC may have other VPN clients installed.
const inspectRoutesScript = `$ErrorActionPreference='Stop';
$nic=Get-NetAdapter -Name 'Portline Tunnel' -ErrorAction Stop;
$default=Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -DestinationPrefix '0.0.0.0/0' |
 Where-Object {$_.NextHop -ne '0.0.0.0' -and $_.InterfaceIndex -ne $nic.ifIndex} |
 Sort-Object RouteMetric | Select-Object -First 1;
if (!$default) {throw 'Cannot detect current IPv4 gateway'}
# A competing /1 route may belong to another VPN or to a previous Portline
# session. Do not remove it or override it; report the interface in a stable
# ASCII format rather than printing an unparseable localized PowerShell stack.
foreach($prefix in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')) {
 $existing=@(Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix $prefix -ErrorAction SilentlyContinue);
 foreach($route in $existing) {
  if(!$route) {continue}
  $owner='external'; if([int]$route.InterfaceIndex -eq [int]$nic.ifIndex) {$owner='portline'}
  Write-Output ('PORTLINE_ROUTE_CONFLICT|'+$prefix+'|'+[int]$route.InterfaceIndex+'|'+$route.NextHop+'|'+$owner)
  exit 48
 }
}
if(Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix ($env:PORTLINE_SERVER_IPV4+'/32') -ErrorAction SilentlyContinue) {throw 'Endpoint already has a static route'}
if(Get-NetIPAddress -IPAddress $env:PORTLINE_CLIENT_IPV4 -ErrorAction SilentlyContinue) {throw 'Tunnel IPv4 address already in use'}
if(Get-NetIPAddress -IPAddress 'fd76:24::2' -ErrorAction SilentlyContinue) {throw 'Tunnel IPv6 address already in use'}
$ipif=Get-NetIPInterface -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction Stop;
$guid=([string]$nic.InterfaceGuid).Trim('{}');
$reg='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{'+$guid+'}';
$nameserver=(Get-ItemProperty -LiteralPath $reg -Name NameServer -ErrorAction SilentlyContinue).NameServer;
$dns=@(); if($nameserver) {$dns=@($nameserver -split '[,;\s]+' | Where-Object {$_})};
$adapterDNS=@();
$others=@(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {$_.ifIndex -ne $nic.ifIndex});
foreach($a in $others) {
 $aguid=([string]$a.InterfaceGuid).Trim('{}');
 if(!$aguid) {continue}
 $areg='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{'+$aguid+'}';
 $ans=(Get-ItemProperty -LiteralPath $areg -Name NameServer -ErrorAction SilentlyContinue).NameServer;
 $adns=@(); if($ans) {$adns=@($ans -split '[,;\s]+' | Where-Object {$_})};
 $curDns=Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue;
 if([int]$a.ifIndex -eq [int]$default.InterfaceIndex -or $adns.Count -gt 0 -or ($curDns -and $curDns.ServerAddresses.Count -gt 0)) {
  $adapterDNS+=[pscustomobject]@{interfaceIndex=[int]$a.ifIndex;staticDNS=$adns}
 }
}
# Physical adapters with IPv6 enabled; routes-only mode disables IPv6 on them
# while connected and re-enables exactly these adapters afterwards.
$v6=@();
foreach($a in $others) {
 $b=$a | Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue;
 if($b -and $b.Enabled) {$v6+=[int]$a.ifIndex}
}
$ver=3; $epPort=0;
if($env:PORTLINE_SERVER_PORT -and [int]$env:PORTLINE_SERVER_PORT -gt 0) { $ver=4; $epPort=[int]$env:PORTLINE_SERVER_PORT }
[pscustomobject]@{version=$ver;dnsGuardID=[string][guid]::NewGuid();endpoint=$env:PORTLINE_SERVER_IPV4;endpointPort=$epPort;physicalInterface=[int]$default.InterfaceIndex;physicalGateway=[string]$default.NextHop;tunnelInterface=[int]$nic.ifIndex;tunnelGUID=[string]$nic.InterfaceGuid;previousMTU=[int]$ipif.NlMtu;staticDNS=$dns;adapterDNS=$adapterDNS;ipv6Adapters=$v6} | ConvertTo-Json -Compress -Depth 4;`

const setRoutesScript = `$ErrorActionPreference='Stop';
$nic=Get-NetAdapter -Name 'Portline Tunnel' -ErrorAction Stop;
if ($nic.ifIndex -ne [int]$env:PORTLINE_TUNNEL_INDEX -or ([string]$nic.InterfaceGuid).Trim('{}') -ne $env:PORTLINE_TUNNEL_GUID.Trim('{}')) {throw 'Portline adapter changed; refusing network modifications'}
# Firewall mode: refuse to connect when local block rules cannot be enforced.
# Routes-only mode (Windows Firewall disabled) skips rules and instead overrides
# DNS on every adapter and disables IPv6 on physical adapters while connected.
# Never enable or change the user's firewall profiles as a side effect of connecting.
if(!$env:PORTLINE_DNS_GUARD_ID) {throw 'Missing DNS guard recovery ID'}
$routesOnly=($env:PORTLINE_GUARD_MODE -eq 'routes');
$ip=$env:PORTLINE_SERVER_IPV4;
if(!$routesOnly) {
$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop);
if(!$profiles.Count -or @($profiles | Where-Object {!$_.Enabled -or $_.AllowLocalFirewallRules -eq $false}).Count) {throw 'DNS protection requires Windows Firewall enabled and local rules allowed on all profiles'}
$outside=@(Get-NetAdapter -ErrorAction Stop | Where-Object {$_.ifIndex -ne $nic.ifIndex -and $_.Status -ne 'Not Present'} | ForEach-Object {$_.Name});
if(!$outside.Count) {throw 'Cannot detect adapters for DNS protection'}
if($env:PORTLINE_BLOCK_IPV4_RANGES) {
 $name='Portline-DNS-'+$env:PORTLINE_DNS_GUARD_ID+'-IPv4';
 New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Group 'Portline DNS protection' -Direction Outbound -Action Block -Enabled True -Profile Any -Protocol Any -RemoteAddress ($env:PORTLINE_BLOCK_IPV4_RANGES -split ',') -InterfaceAlias $outside -ErrorAction Stop | Out-Null;
 if($env:PORTLINE_BLOCK_TCP_PORTS) {
  $name='Portline-DNS-'+$env:PORTLINE_DNS_GUARD_ID+'-EndpointTCP';
  New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Group 'Portline DNS protection' -Direction Outbound -Action Block -Enabled True -Profile Any -Protocol TCP -RemoteAddress $ip -RemotePort ($env:PORTLINE_BLOCK_TCP_PORTS -split ',') -InterfaceAlias $outside -ErrorAction Stop | Out-Null;
 }
 $name='Portline-DNS-'+$env:PORTLINE_DNS_GUARD_ID+'-EndpointUDP';
 New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Group 'Portline DNS protection' -Direction Outbound -Action Block -Enabled True -Profile Any -Protocol UDP -RemoteAddress $ip -InterfaceAlias $outside -ErrorAction Stop | Out-Null;
 $name='Portline-DNS-'+$env:PORTLINE_DNS_GUARD_ID+'-IPv6';
 New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Group 'Portline DNS protection' -Direction Outbound -Action Block -Enabled True -Profile Any -Protocol Any -RemoteAddress @('::/1','8000::/1') -InterfaceAlias $outside -ErrorAction Stop | Out-Null;
} else {
 foreach($protocol in @('UDP','TCP')) {
  $name='Portline-DNS-'+$env:PORTLINE_DNS_GUARD_ID+'-'+$protocol;
  New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Group 'Portline DNS protection' -Direction Outbound -Action Block -Enabled True -Profile Any -Protocol $protocol -RemotePort 53 -InterfaceAlias $outside -ErrorAction Stop | Out-Null;
 }
}
}
$physical=[int]$env:PORTLINE_PHYSICAL_INDEX;
$gateway=$env:PORTLINE_PHYSICAL_GATEWAY;
New-NetRoute -PolicyStore ActiveStore -DestinationPrefix ($ip+'/32') -InterfaceIndex $physical -NextHop $gateway -RouteMetric 1 -ErrorAction Stop | Out-Null;
Set-NetIPInterface -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -NlMtuBytes 1280 -InterfaceMetric 1 -ErrorAction Stop;
New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $env:PORTLINE_CLIENT_IPV4 -PrefixLength 16 -AddressFamily IPv4 -ErrorAction Stop | Out-Null;
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses @('1.1.1.1','9.9.9.9') -ErrorAction Stop;
if(Get-Command Set-DnsClient -ErrorAction SilentlyContinue) { Set-DnsClient -InterfaceIndex $nic.ifIndex -RegisterThisConnectionsAddress $false -ErrorAction SilentlyContinue };
if($env:PORTLINE_ADAPTER_DNS) {
 foreach($entry in ($env:PORTLINE_ADAPTER_DNS -split ';')) {
  if(!$entry) {continue}
  $parts=$entry -split '=',2;
  $idx=[int]$parts[0];
  if($idx -gt 0 -and $idx -ne $nic.ifIndex) {
   # Without firewall rules this override is the main DNS protection: fail closed.
   if($routesOnly) {Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses @('1.1.1.1','9.9.9.9') -ErrorAction Stop}
   else {Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses @('1.1.1.1','9.9.9.9') -ErrorAction SilentlyContinue}
  }
 }
}
if($env:PORTLINE_IPV6_ADAPTERS) {
 foreach($i in ($env:PORTLINE_IPV6_ADAPTERS -split ',')) {
  if(!$i) {continue}
  $v6idx=[int]$i;
  if($v6idx -gt 0 -and $v6idx -ne $nic.ifIndex) {
   Get-NetAdapter -InterfaceIndex $v6idx -ErrorAction SilentlyContinue | Disable-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop;
  }
 }
}
if(Get-Command Add-DnsClientNrptRule -ErrorAction SilentlyContinue) {
 $nrptTag='Portline-DNS-'+$env:PORTLINE_DNS_GUARD_ID;
 Add-DnsClientNrptRule -Namespace '.' -NameServers @('1.1.1.1','9.9.9.9') -Comment $nrptTag -ErrorAction SilentlyContinue | Out-Null;
}
if(Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue) { Clear-DnsClientCache -ErrorAction SilentlyContinue };
New-NetRoute -PolicyStore ActiveStore -DestinationPrefix '0.0.0.0/1' -InterfaceIndex $nic.ifIndex -NextHop '0.0.0.0' -RouteMetric 1 -ErrorAction Stop | Out-Null;
New-NetRoute -PolicyStore ActiveStore -DestinationPrefix '128.0.0.0/1' -InterfaceIndex $nic.ifIndex -NextHop '0.0.0.0' -RouteMetric 1 -ErrorAction Stop | Out-Null;
# IPv6 transport is not implemented; these routes direct IPv6 into the
# TUN where Portline replies with ICMPv6 Admin Prohibited for fast fail.
New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress 'fd76:24::2' -PrefixLength 64 -AddressFamily IPv6 -ErrorAction Stop | Out-Null;
New-NetRoute -PolicyStore ActiveStore -DestinationPrefix '::/1' -InterfaceIndex $nic.ifIndex -NextHop '::' -RouteMetric 1 -ErrorAction Stop | Out-Null;
New-NetRoute -PolicyStore ActiveStore -DestinationPrefix '8000::/1' -InterfaceIndex $nic.ifIndex -NextHop '::' -RouteMetric 1 -ErrorAction Stop | Out-Null;`

const cleanupRoutesScript = `$ErrorActionPreference='Stop';
$nic=Get-NetAdapter -Name 'Portline Tunnel' -ErrorAction SilentlyContinue;
if($nic) {
 if(([string]$nic.InterfaceGuid).Trim('{}') -ne $env:PORTLINE_TUNNEL_GUID.Trim('{}')) {throw 'Portline adapter identity mismatch; manual network recovery required'}
 $index=[int]$nic.ifIndex;
 foreach($prefix in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')) {
  $hop='0.0.0.0'; if($prefix -like '*::*') {$hop='::'};
  Get-NetRoute -PolicyStore ActiveStore -InterfaceIndex $index -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
   Where-Object {$_.NextHop -eq $hop -and $_.RouteMetric -eq 1} |
   Remove-NetRoute -Confirm:$false -ErrorAction Stop;
 }
 foreach($address in @($env:PORTLINE_CLIENT_IPV4,'fd76:24::2')) {
  Get-NetIPAddress -InterfaceIndex $index -IPAddress $address -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop;
 }
 $current=Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction SilentlyContinue;
 if($current -and (($current.ServerAddresses -join ',') -eq '1.1.1.1,9.9.9.9')) {
  if($env:PORTLINE_PREVIOUS_DNS) {Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses ($env:PORTLINE_PREVIOUS_DNS -split ',') -ErrorAction Stop}
  else {Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses -ErrorAction Stop}
 }
 $ipif=Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction SilentlyContinue;
 if($ipif -and $ipif.NlMtu -eq 1280) {Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -NlMtuBytes ([int]$env:PORTLINE_PREVIOUS_MTU) -ErrorAction Stop}
} else {
 # An absent adapter normally removes its routes. If old interface-index
 # routes still exist, never claim that recovery has succeeded.
 foreach($prefix in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')) {
  if(Get-NetRoute -PolicyStore ActiveStore -InterfaceIndex ([int]$env:PORTLINE_TUNNEL_INDEX) -DestinationPrefix $prefix -ErrorAction SilentlyContinue) {throw 'Orphaned Portline routes require manual review'}
 }
}
if($env:PORTLINE_ADAPTER_DNS) {
 foreach($entry in ($env:PORTLINE_ADAPTER_DNS -split ';')) {
  if(!$entry) {continue}
  $parts=$entry -split '=',2;
  $idx=[int]$parts[0];
  if($idx -gt 0) {
   if($parts.Count -gt 1 -and $parts[1]) {
    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses ($parts[1] -split ',') -ErrorAction SilentlyContinue
   } else {
    Set-DnsClientServerAddress -InterfaceIndex $idx -ResetServerAddresses -ErrorAction SilentlyContinue
   }
  }
 }
}
if($env:PORTLINE_DNS_GUARD_ID -and (Get-Command Get-DnsClientNrptRule -ErrorAction SilentlyContinue)) {
 $nrptTag='Portline-DNS-'+$env:PORTLINE_DNS_GUARD_ID;
 Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object {$_.Comment -eq $nrptTag} | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue;
}
if(Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue) { Clear-DnsClientCache -ErrorAction SilentlyContinue };
# Re-enable IPv6 only on adapters where it was enabled before connecting.
if($env:PORTLINE_IPV6_ADAPTERS) {
 foreach($i in ($env:PORTLINE_IPV6_ADAPTERS -split ',')) {
  if(!$i) {continue}
  $v6idx=[int]$i;
  if($v6idx -gt 0) {
   Get-NetAdapter -InterfaceIndex $v6idx -ErrorAction SilentlyContinue | Enable-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop;
  }
 }
}
Get-NetRoute -PolicyStore ActiveStore -AddressFamily IPv4 -InterfaceIndex ([int]$env:PORTLINE_PHYSICAL_INDEX) -DestinationPrefix ($env:PORTLINE_SERVER_IPV4+'/32') -ErrorAction SilentlyContinue |
 Where-Object {$_.NextHop -eq $env:PORTLINE_PHYSICAL_GATEWAY -and $_.RouteMetric -eq 1} |
 Remove-NetRoute -Confirm:$false -ErrorAction Stop;
# Keep firewall protection active if route recovery fails; retry using the saved journal.
if($env:PORTLINE_DNS_GUARD_ID) {
 $prefix='Portline-DNS-'+$env:PORTLINE_DNS_GUARD_ID+'-';
 Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object {$_.Name -like ($prefix+'*')} |
  Remove-NetFirewallRule -ErrorAction Stop;
}`

func journalPath() (string, error) {
	dir, err := appDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "network-recovery.json"), nil
}

func excludeIPv4Ranges(ipStr string) string {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return ""
	}
	v := binary.BigEndian.Uint32(ip)
	var ranges []string
	if v > 0 {
		var prev [4]byte
		binary.BigEndian.PutUint32(prev[:], v-1)
		ranges = append(ranges, "0.0.0.0-"+net.IP(prev[:]).String())
	}
	if v < 0xffffffff {
		var next [4]byte
		binary.BigEndian.PutUint32(next[:], v+1)
		ranges = append(ranges, net.IP(next[:]).String()+"-255.255.255.255")
	}
	return strings.Join(ranges, ",")
}

func excludePortRanges(port int) string {
	if port < 1 || port > 65535 {
		return ""
	}
	var ranges []string
	if port > 1 {
		ranges = append(ranges, fmt.Sprintf("1-%d", port-1))
	}
	if port < 65535 {
		ranges = append(ranges, fmt.Sprintf("%d-65535", port+1))
	}
	return strings.Join(ranges, ",")
}

func formatAdapterDNS(records []adapterDNSRecord) string {
	if len(records) == 0 {
		return ""
	}
	parts := make([]string, 0, len(records))
	for _, rec := range records {
		parts = append(parts, fmt.Sprintf("%d=%s", rec.InterfaceIndex, strings.Join(rec.StaticDNS, ",")))
	}
	return strings.Join(parts, ";")
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, fmt.Sprint(v))
	}
	return strings.Join(parts, ",")
}

func routeEnvironment(r routeJournal) []string {
	clientIP := r.ClientIP
	if clientIP == "" {
		clientIP = ptunnel.ClientIP
	}
	env := []string{
		"PORTLINE_DNS_GUARD_ID=" + r.DNSGuardID,
		"PORTLINE_CLIENT_IPV4=" + clientIP,
		"PORTLINE_SERVER_IPV4=" + r.Endpoint,
		fmt.Sprintf("PORTLINE_SERVER_PORT=%d", r.EndpointPort),
		fmt.Sprintf("PORTLINE_TUNNEL_INDEX=%d", r.TunnelInterface),
		"PORTLINE_TUNNEL_GUID=" + strings.Trim(r.TunnelGUID, "{}"),
		fmt.Sprintf("PORTLINE_PHYSICAL_INDEX=%d", r.PhysicalInterface),
		"PORTLINE_PHYSICAL_GATEWAY=" + r.PhysicalGateway,
		fmt.Sprintf("PORTLINE_PREVIOUS_MTU=%d", r.PreviousMTU),
		"PORTLINE_PREVIOUS_DNS=" + strings.Join(r.StaticDNS, ","),
		"PORTLINE_ADAPTER_DNS=" + formatAdapterDNS(r.AdapterDNS),
		"PORTLINE_GUARD_MODE=" + r.GuardMode,
		"PORTLINE_IPV6_ADAPTERS=" + joinInts(r.IPv6Adapters),
	}
	if r.Version >= 4 && r.EndpointPort > 0 {
		if ranges := excludeIPv4Ranges(r.Endpoint); ranges != "" {
			env = append(env, "PORTLINE_BLOCK_IPV4_RANGES="+ranges)
		}
		if ports := excludePortRanges(r.EndpointPort); ports != "" {
			env = append(env, "PORTLINE_BLOCK_TCP_PORTS="+ports)
		}
	}
	return env
}

func runPSOutput(ctx context.Context, script string, env ...string) ([]byte, error) {
	cmd := backgroundCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), env...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if message, recognized := explainWindowsRouteConflict(output); recognized {
			return nil, errors.New(message)
		}
		return nil, fmt.Errorf("network inspection failed: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func inspectRoutes(ctx context.Context, endpoint string, endpointPort int, clientIP string) (routeJournal, error) {
	var r routeJournal
	raw, err := runPSOutput(ctx, inspectRoutesScript,
		"PORTLINE_SERVER_IPV4="+endpoint,
		fmt.Sprintf("PORTLINE_SERVER_PORT=%d", endpointPort),
		"PORTLINE_CLIENT_IPV4="+clientIP,
	)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(raw, &r); err != nil {
		return r, fmt.Errorf("invalid Windows network inspection result: %w", err)
	}
	// Older clients must refuse recovery when the saved address is not their fixed .2.
	if clientIP != ptunnel.ClientIP {
		r.ClientIP = clientIP
	}
	if err = r.validate(); err != nil {
		return r, err
	}
	return r, nil
}

func recoverWindowsRoutes() error {
	path, err := journalPath()
	if err != nil {
		return err
	}
	return recoverRoutes(path, func(r routeJournal) error {
		if !isAdmin() {
			return errors.New("Network recovery needs Windows administrator rights; restart Portline as administrator")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		return runPS(ctx, cleanupRoutesScript, routeEnvironment(r)...)
	})
}

func recoverStartupRoutes() error { return recoverWindowsRoutes() }

type nativeSession struct {
	tunnelTraffic
	guardMode  string
	wfp        *wfpGuard
	done       chan struct{}
	stop       context.CancelFunc
	once       sync.Once
	cleanupMu  sync.Mutex
	cleanupErr error
}

func (s *nativeSession) Stop()                 { s.once.Do(func() { s.stop(); <-s.done }) }
func (s *nativeSession) Done() <-chan struct{} { return s.done }
func (s *nativeSession) CleanupError() error {
	s.cleanupMu.Lock()
	defer s.cleanupMu.Unlock()
	return s.cleanupErr
}
func (s *nativeSession) setCleanupError(err error) {
	s.cleanupMu.Lock()
	s.cleanupErr = err
	s.cleanupMu.Unlock()
}

func lockProfileFile(path string) error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	cmd := backgroundCommand(context.Background(), "icacls.exe", path, "/inheritance:r", "/grant:r", "*"+u.Uid+":F", "*S-1-5-18:F", "*S-1-5-32-544:F")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed restricting profile access: %w (%s)", err, string(output))
	}
	return nil
}

// errFirewallDisabled is kept for callers; startNativeTunnel now falls back to
// routes-only protection instead of returning it.
var errFirewallDisabled = errors.New("firewall disabled")

const firewallCheckScript = `$ErrorActionPreference='Stop';
$bad=@(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object {!$_.Enabled -or $_.AllowLocalFirewallRules -eq $false} | ForEach-Object {$_.Name});
if($bad.Count) {Write-Output ('PORTLINE_FIREWALL_OFF|'+($bad -join ','))} else {Write-Output 'PORTLINE_FIREWALL_OK'}`

// firewallReady reports whether every firewall profile is enabled and accepts
// local rules. It never changes the configuration.
func firewallReady(ctx context.Context) (bool, string, error) {
	out, err := runPSOutput(ctx, firewallCheckScript)
	if err != nil {
		return false, "", err
	}
	text := strings.TrimSpace(string(out))
	if strings.HasPrefix(text, "PORTLINE_FIREWALL_OFF|") {
		return false, strings.TrimPrefix(text, "PORTLINE_FIREWALL_OFF|"), nil
	}
	return text == "PORTLINE_FIREWALL_OK", "", nil
}

// enableFirewall is only called after an explicit user confirmation in the UI.
// Default inbound/outbound actions and existing rules are left unchanged.
func enableFirewall(ctx context.Context) error {
	if !isAdmin() {
		return errors.New("Нужны права администратора Windows. Запусти Portline от имени администратора.")
	}
	return runPS(ctx, `$ErrorActionPreference='Stop'; Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -AllowLocalFirewallRules True -ErrorAction Stop`)
}

func startNativeTunnel(ctx context.Context, p ptunnel.Profile, report func(string)) (*nativeSession, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if !isAdmin() {
		return nil, errors.New("Для настройки системного туннеля нужны права администратора Windows. Запусти Portline от имени администратора.")
	}
	report("Проверяем брандмауэр Windows")
	guardMode := "firewall"
	if ok, _, err := firewallReady(ctx); err != nil {
		return nil, fmt.Errorf("Не удалось проверить брандмауэр Windows: %w", err)
	} else if !ok {
		// Routes-only protection: DNS override on all adapters + IPv6 disabled
		// on physical adapters while connected. Weaker than firewall rules.
		guardMode = "routes"
		report("Брандмауэр выключен — защита через маршруты, DNS и отключение IPv6")
	}
	report("Подключаемся к VPS и проверяем ключ сервера")
	tlsConfig, err := p.TLSConfig()
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 20 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", p.Endpoint())
	if err != nil {
		return nil, err
	}
	endpoint := rawConn.RemoteAddr().(*net.TCPAddr).IP.To4()
	if endpoint == nil {
		rawConn.Close()
		return nil, errors.New("IPv6 endpoint не поддерживается")
	}
	conn := tls.Client(rawConn, tlsConfig)
	if err = conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS-рукопожатие с %s: %w", p.Endpoint(), err)
	}
	secret, _ := base64.RawURLEncoding.DecodeString(p.Token)
	if _, err = conn.Write(secret); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var accepted [1]byte
	if _, err = io.ReadFull(conn, accepted[:]); err != nil || accepted[0] != 1 {
		conn.Close()
		return nil, fmt.Errorf("Сервер не подтвердил ключ подключения (%s)", p.Endpoint())
	}
	clientIP := ptunnel.ClientIP
	if conn.ConnectionState().NegotiatedProtocol == ptunnel.LeaseProtocol {
		ip := make(net.IP, 4)
		if _, err = io.ReadFull(conn, ip); err != nil || !ptunnel.ValidClientIP(ip.String()) {
			conn.Close()
			return nil, errors.New("Gateway вернул некорректный адрес клиента")
		}
		clientIP = ip.String()
	}
	_ = conn.SetReadDeadline(time.Time{})
	report("Подготавливаем сетевой адаптер Windows")
	dll, err := ensureWintun(ctx, report)
	if err != nil {
		conn.Close()
		return nil, err
	}
	adapter, err := newWintun(dll)
	if err != nil {
		conn.Close()
		return nil, err
	}
	report("Проверяем маршруты и сохраняем план восстановления")
	if err = recoverWindowsRoutes(); err != nil {
		adapter.Close()
		conn.Close()
		return nil, fmt.Errorf("Не удалось восстановить маршруты предыдущего подключения: %w", err)
	}
	snapshot, err := inspectRoutes(ctx, endpoint.String(), p.Port, clientIP)
	if err != nil {
		adapter.Close()
		conn.Close()
		return nil, err
	}
	snapshot.GuardMode = guardMode
	path, err := journalPath()
	if err != nil {
		adapter.Close()
		conn.Close()
		return nil, err
	}
	report("Настраиваем системные маршруты IPv4 и IPv6")
	if err = beginRoutes(path, snapshot,
		func(r routeJournal) error { return runPS(ctx, setRoutesScript, routeEnvironment(r)...) },
		func(r routeJournal) error {
			restoreCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			return runPS(restoreCtx, cleanupRoutesScript, routeEnvironment(r)...)
		}); err != nil {
		adapter.Close()
		conn.Close()
		return nil, err
	}
	var wfp *wfpGuard
	if g, wfpErr := newWFPGuard(snapshot.TunnelInterface, endpoint.String(), p.Port); wfpErr == nil {
		wfp = g
		guardMode = "wfp"
	}
	sessionCtx, stop := context.WithCancel(context.Background())
	session := &nativeSession{done: make(chan struct{}), stop: stop, guardMode: guardMode, wfp: wfp}
	go session.run(sessionCtx, conn, adapter, clientIP, recoverWindowsRoutes)
	return session, nil
}

type packetDevice interface {
	ReadPacket(context.Context) ([]byte, error)
	WritePacket([]byte) error
	Close()
}

const portlineEchoID = 0x504C

func checksum16(sum uint32, b []byte) uint16 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildICMPv6AdminProhibited synthesizes an ICMPv6 Type 1 Code 1 (Administratively
// Prohibited) packet so Windows fails IPv6 sockets immediately instead of timing out.
func buildICMPv6AdminProhibited(orig []byte) ([]byte, bool) {
	if len(orig) < 40 || orig[0]>>4 != 6 {
		return nil, false
	}
	// Never reply to ICMPv6 error messages (types 1..4) or neighbor discovery (133..136).
	if orig[6] == 58 && len(orig) >= 48 {
		icmpType := orig[40]
		if icmpType < 128 || (icmpType >= 133 && icmpType <= 136) {
			return nil, false
		}
	}
	// Multicast destinations must not trigger ICMPv6 errors.
	if orig[24] == 0xff {
		return nil, false
	}
	maxQuoted := ptunnel.MTU - 48
	quotedLen := len(orig)
	if quotedLen > maxQuoted {
		quotedLen = maxQuoted
	}
	pkt := make([]byte, 48+quotedLen)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(8+quotedLen))
	pkt[6] = 58 // ICMPv6
	pkt[7] = 64 // HopLimit
	copy(pkt[8:24], orig[24:40])
	copy(pkt[24:40], orig[8:24])
	pkt[40] = 1 // Destination Unreachable
	pkt[41] = 1 // Communication with destination administratively prohibited
	copy(pkt[48:], orig[:quotedLen])

	var pseudo uint32
	for i := 8; i < 40; i += 2 {
		pseudo += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	icmpLen := uint32(8 + quotedLen)
	pseudo += icmpLen + 58
	binary.BigEndian.PutUint16(pkt[42:44], checksum16(pseudo, pkt[40:]))
	return pkt, true
}

func buildICMPEchoRequest(srcIP, dstIP string, seq uint16) []byte {
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	if src == nil || dst == nil {
		return nil
	}
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	pkt[8] = 64
	pkt[9] = 1 // ICMP
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	binary.BigEndian.PutUint16(pkt[10:12], checksum16(0, pkt[:20]))
	pkt[20] = 8 // Echo Request
	binary.BigEndian.PutUint16(pkt[24:26], portlineEchoID)
	binary.BigEndian.PutUint16(pkt[26:28], seq)
	binary.BigEndian.PutUint16(pkt[22:24], checksum16(0, pkt[20:]))
	return pkt
}

func isPortlineICMPEchoReply(pkt []byte) (uint16, bool) {
	if len(pkt) < 28 || pkt[0]>>4 != 4 || pkt[9] != 1 {
		return 0, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return 0, false
	}
	if pkt[ihl] != 0 || pkt[ihl+1] != 0 {
		return 0, false
	}
	if binary.BigEndian.Uint16(pkt[ihl+4:ihl+6]) != portlineEchoID {
		return 0, false
	}
	return binary.BigEndian.Uint16(pkt[ihl+6 : ihl+8]), true
}

func (s *nativeSession) run(sessionCtx context.Context, conn net.Conn, adapter packetDevice, clientIP string, cleanup func() error) {
	defer close(s.done)
	defer adapter.Close()
	defer conn.Close()
	defer func() {
		if s.wfp != nil {
			s.wfp.Close()
		}
		s.setCleanupError(cleanup())
	}()
	s.latencyMs.Store(-1)
	var writeMu sync.Mutex
	writeTunnel := func(pkt []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		return ptunnel.WritePacket(conn, pkt)
	}
	var pingMu sync.Mutex
	var lastPingSeq uint16
	var lastPingSent time.Time

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			packet, err := adapter.ReadPacket(sessionCtx)
			if err != nil {
				s.stop()
				return
			}
			if len(packet) >= 40 && packet[0]>>4 == 6 {
				if reply, ok := buildICMPv6AdminProhibited(packet); ok {
					_ = adapter.WritePacket(reply)
				}
				continue
			}
			if len(packet) < 20 || packet[0]>>4 != 4 {
				continue
			}
			if err = writeTunnel(packet); err != nil {
				s.stop()
				return
			}
			s.sent.Add(1)
		}
	}()
	go func() {
		ticker := time.NewTicker(12 * time.Second)
		defer ticker.Stop()
		var seq uint16
		for {
			select {
			case <-sessionCtx.Done():
				return
			case <-ticker.C:
				seq++
				ping := buildICMPEchoRequest(clientIP, ptunnel.ServerIP, seq)
				if ping == nil {
					continue
				}
				pingMu.Lock()
				lastPingSeq = seq
				lastPingSent = time.Now()
				pingMu.Unlock()
				if err := writeTunnel(ping); err != nil {
					s.stop()
					return
				}
			}
		}
	}()
	go func() { <-sessionCtx.Done(); _ = conn.Close() }()
	readBuf := make([]byte, ptunnel.MTU)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(45 * time.Second))
		data, err := ptunnel.ReadPacket(conn, readBuf)
		if err != nil {
			break
		}
		if !ptunnel.DestinationIs(data, clientIP) {
			break
		}
		if seq, ok := isPortlineICMPEchoReply(data); ok {
			pingMu.Lock()
			if seq == lastPingSeq && !lastPingSent.IsZero() {
				ms := time.Since(lastPingSent).Milliseconds()
				if ms < 1 {
					ms = 1
				}
				s.latencyMs.Store(ms)
			}
			pingMu.Unlock()
			continue
		}
		if err = adapter.WritePacket(data); err != nil {
			break
		}
		s.received.Add(1)
	}
	s.stop()
	_ = conn.Close()
	<-readDone
}

func isAdmin() bool {
	dll := syscall.NewLazyDLL("shell32.dll")
	proc := dll.NewProc("IsUserAnAdmin")
	result, _, _ := proc.Call()
	return result != 0
}
