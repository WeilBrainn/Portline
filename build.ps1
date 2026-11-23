# Build and test Portline from source. Run from Windows PowerShell.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw 'Go 1.21+ is required: https://go.dev/dl/' }
& go test ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
New-Item -ItemType Directory -Force -Path bin | Out-Null
$env:CGO_ENABLED = '0'
$env:GOOS = 'linux'
$env:GOARCH = 'amd64'
& go build -trimpath -ldflags='-s -w' -o 'bin/portline-gateway-linux-amd64' ./cmd/portline-gateway
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$env:GOOS = 'windows'
& go build -trimpath -ldflags='-H windowsgui -s -w' -o Portline.exe .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host 'Built Portline.exe and bin/portline-gateway-linux-amd64'
