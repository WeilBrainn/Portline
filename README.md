# Portline — own tunnel implementation (experimental)

Portline is a Windows desktop utility (Go backend, embedded local HTML/CSS/JS UI) that can install and manage VPN software on a Linux VPS over SSH. This branch adds **Portline Tunnel**, an independent client and Linux server written in Go. This is **not** a modified AmneziaWG client, and it does not embed HAPP, sing-box, or Xray as its native client engine. Existing VLESS + REALITY and Hysteria 2 *server installers* remain available as legacy options.

**Preview, not a production security release.** No end-to-end Windows/VPS network test, external security review, or leak test has been performed. The custom transport will likely be easier to identify as VPN traffic than well-established obfuscated protocols. Do not use it for sensitive traffic yet.

## Architecture

- `internal/ptunnel/` — profile schema, packet framing, TLS certificate public-key pinning. All encryption uses the Go standard library TLS 1.3 implementation. The framing protocol is Portline's, not HAPP/Amnezia's.
- `cmd/portline-gateway/` — Linux tunnel gateway, system TUN, IPv4 forwarding and NAT using iproute2/iptables. Runs under a dedicated systemd unit.
- `tunnel_windows.go` — Windows client: TLS 1.3 session, signed Wintun adapter, network routing and cleanup using Windows networking APIs/PowerShell. Wintun is a generic signed TUN driver, not a VPN engine. **Windows administrator rights are required** for configuring routes; currently launch Portline as Administrator for native connection.
- `scripts/portline.sh` — idempotent Linux install for AlmaLinux/RHEL and Debian/Ubuntu, bundled gateway binary is transferred over SSH and SHA-256 checked.
- `tunnel.go` — connection lifecycle, profile persistence, secret redaction, status handling.

## Installation / use

1. Run `Portline.exe` as Administrator on Windows 10/11 x64. Administrator is required only for network-adapter operations. UAC consent is OS-managed.
2. Enter VPS SSH information (root, or a sudo user configured for passwordless sudo).
3. Select **Portline Tunnel**, use unused **TCP 8443** unless you have a reason for another port, install on VPS.
4. Portline keeps its server credentials in the app config directory and attempts a connection. A pinned signed Wintun DLL is downloaded from the official Wintun distribution if necessary.
5. Check public IPv4, IPv6 routing and DNS. Do not assume the system is protected just because Portline shows 'connected'.

VPS requirements: x86_64 Linux with systemd, `/dev/net/tun`, outbound internet, `ip` and `iptables`, TCP port open in host firewall and hosting control panel. Existing Xray/Hysteria are left installed.

The gateway creates `/etc/portline/gateway.json` with private key and access token (mode 0600) and `portline-gateway.service`. Retrying setup with the same host and port reuses its keys. An attempt to change the host/port of an existing gateway fails without silently overwriting credentials. For a different port, use a clean VPS or explicitly migrate the gateway configuration yourself.

The Windows profile is stored under the current user's Portline application configuration directory, restricted to that account, SYSTEM, and Administrators. Never commit real profiles or private keys.

## Limitations

- Native tunnel supports **IPv4 only**. The Windows implementation attempts to blackhole IPv6 via explicit IPv6 routes; verify IPv6 leakage on a real device.
- v0.9 records network changes before applying routes and attempts scoped recovery on the next launch (Administrator privileges required). This is **not** an automatic background recovery service. There is still no persistent kill switch, split tunneling, or reliable reconnection policy. A crash may leave connectivity unprotected until Portline starts again; do not use as a primary privacy VPN.
- TCP tunnel transport can have head-of-line blocking and is not an obfuscation or stealth guarantee.
- Portline cannot guarantee that Anthropic, Google, or another service will accept a connection or an account from an unsupported region. Providers can identify VPN/datacenter IPs and use account-level signals.
- On Windows, if the signed Wintun archive cannot be downloaded/verified or the signing check fails, the client refuses to connect rather than executing an unknown DLL.
- The first real Windows route/TUN test and AlmaLinux server integration test have not been performed in this development environment.

## Build from source

Go 1.21+ is required. npm, Node.js and external Go modules are **not** required to build. Windows and Linux builds cross-compile using the Go toolchain.

On Windows, double-click `build.bat` in the project folder (Go must be installed), or run:

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

Windows does **not** require WSL or Bash to build. The X25519 installer
regression test executes only if a working Bash interpreter is available.
A Windows `bash.exe` launcher pointing to a broken WSL distribution is detected
and that test is skipped; the Linux CI job runs the real Bash parser tests.

On Arch Linux:

```bash
bash ./build.sh
```

Both scripts first run tests, then compile the Linux gateway binary into `bin/`, and finally compile the app with the gateway embedded. Simply running `go build .` without rebuilding the gateway could embed a stale binary.

Validation:

```bash
go test ./...
go test -race ./...
go vet ./...
bash -n scripts/*.sh
node --check ui/app.js
```

## Compatibility

The older VLESS/REALITY and Hysteria 2 server provisioning routines are preserved for external clients only. The direct Portline Tunnel **cannot connect to an existing VLESS or Hysteria URI**, so do not remove a working service until you've tested the new mode.

Third-party attribution: Wintun (https://www.wintun.net/), signed low-level Windows TUN adapter. Include the Wintun prebuilt binaries license when redistributing it. Portline fetches Wintun from its official release and verifies its release archive SHA-256.

## Network recovery changes (v0.9 preview)

- A disk-synced recovery journal in the user Portline configuration directory records endpoint, interfaces, MTU and adapter DNS before route changes. The marker is removed only after cleanup.
- On next startup, a single Portline instance attempts to restore its own routes before opening the interface; if it cannot, it reports an error and keeps the recovery file.
- Route cleanup is scoped by interface, next hop, prefix and metric rather than removing all matching host routes.

## Gateway discovery and Android preview

The Portline protocol selection step includes **Проверить Gateway**, **Использовать существующий сервер**, and a confirmation-gated update with backups. Build the Android client with the Gradle wrapper in [android/README.md](android/README.md). Gateway 1.4.0 supports simultaneous sessions on one TCP port. Export the VPN profile in the connection panel and import it on the other device.

## Route-conflict diagnostic (Windows)

If Portline reports a route such as `0.0.0.0/1` or `128.0.0.0/1` already exists, the Portline TCP/TLS and access-token check has already succeeded, but network setup has stopped **before changing your routes**. Run `Check-Windows-Routes.bat` (read-only). It lists each /1 route, its interface index and adapter name.

- If a different VPN client owns the route, disconnect it in **that client** and retry Portline.
- If `Portline Tunnel` owns the route, restart Portline as administrator so it can recover its own recorded routes. If the recovery journal is absent or inconsistent, manual network review is necessary.
- **Do not automatically remove all /1 routes**; they may be intentional VPN/security settings.

This preflight remains a safety check, not a persistent kill switch. Connection state and leak behavior still require Windows testing.
