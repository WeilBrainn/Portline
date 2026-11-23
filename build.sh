#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
command -v go >/dev/null || { echo 'Go 1.21+ required' >&2; exit 1; }
go test ./...
mkdir -p bin
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/portline-gateway-linux-amd64 ./cmd/portline-gateway
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o Portline-linux-amd64 .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-H windowsgui -s -w' -o Portline.exe .
echo 'Built Portline.exe, Portline-linux-amd64 and the gateway binary'
