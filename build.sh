#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
command -v go >/dev/null || { echo 'Install the Go compiler: https://go.dev/dl/' >&2; exit 1; }
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o portline-linux-amd64 .
echo "Done: $PWD/portline-linux-amd64"
