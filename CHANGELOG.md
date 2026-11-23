# Changelog

## v1.4.0-preview (2026-11-23)
- Stop the native session and restore network configuration on fatal Wintun receive errors; retry only an empty receive queue.
- Drop packets on a full Wintun send ring instead of disconnecting the tunnel.
- Exercise driver errors, peer loss, a fresh session, IPv6 filtering, and DNS/MTU/route rollback in isolated tests.
- Isolate Windows test configuration from the active user's profiles and recovery journal.
- Persistent crash protection and DNS leak freedom remain unverified; no WFP kill switch is implemented.

## v1.3.1-route-preflight-preview (2026-11-23)
- Distinguish a pre-existing `/1` route on the Portline adapter from one belonging to another adapter.
- Return concise route-conflict messages without localized PowerShell error stacks.
- Keep the safety block: never automatically delete or override existing full-tunnel routes.
- Add a read-only Windows route inspection batch file.
- These changes affect client-side diagnostics only; no change to the Linux gateway protocol.
- Actual Windows and VPS integration and leak tests remain outstanding.

## v1.1.1-bash-compat (2026-11-22)
- Fix Windows `go test` failure when `bash.exe` is installed but WSL has no `/bin/bash`.
- Probe the Bash interpreter before executing the X25519 shell parser regression cases.
- Keep the real parser tests on Linux/CI and add an Ubuntu test job.
- Keep the existing `build.bat` and `build.ps1` entry points for Windows builds.
- This is a build/test compatibility fix; it does not change the VPN transport.

## v0.9.0-recovery-preview (2026-11-22)
- Persist and validate a route recovery record before Windows network changes; restore on next startup or disconnection.
- Restrict cleanup to the Portline adapter GUID and recorded endpoint route.
- Prevent two Windows processes from managing the same tunnel.
- Surface rollback errors to the GUI and retain the journal for subsequent recovery attempts.
- Fix an SSH stream read/Wait race that intermittently dropped command output.
- Add regression tests and Windows system test plan. No validated persistent kill switch yet.


## v0.7.0-custom-preview

- Replaced the proposed AmneziaWG client integration with a standalone Portline Tunnel protocol and Go Linux gateway.
- Added TLS 1.3 server identity pinning, random per-install access credential, simple framed IPv4 transport and Windows Wintun adapter bridge.
- Introduced IPv4 routing with server host-route exemption and best-effort IPv6 blocking, plus teardown actions.
- Kept previous server-only installers for VLESS + REALITY and Hysteria 2.
- Added unit tests for wire frames, identity pinning and server provisioning idempotency.
- Marked custom tunnel as an experimental technical preview pending real Windows/VPS tests.

## 0.8.0-review-preview (2026-11-22)
- Local API now rejects non-loopback Host headers before serving token-bearing HTML.
- Guard against a second native tunnel connection on an already active session.
- Rebuild embedded Linux gateway from current source in GitHub Actions.
- Handle partial writes of the packet length header correctly.
- Add regression tests and `REVIEW-SUPERPOWERS-PONYTAIL.md`; document release blockers.
