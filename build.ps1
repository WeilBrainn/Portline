# Run from the project directory: powershell -ExecutionPolicy Bypass -File .\build.ps1
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
  Write-Host 'Go is not installed. Download Go from https://go.dev/dl/' -ForegroundColor Red
  exit 1
}
$env:CGO_ENABLED = '0'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
Write-Host 'Running automated tests...'
& go test ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host 'Building Portline.exe...'
& go build -trimpath -ldflags='-H windowsgui -s -w' -o Portline.exe .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Done: $PSScriptRoot\Portline.exe" -ForegroundColor Green
