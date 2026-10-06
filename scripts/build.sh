#!/usr/bin/env bash
# Docker-first build: compiles the binary inside the official Go image
# (same version as go.mod and the Dockerfile builder stage), so no Go
# toolchain is needed on the host.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/_run.sh"

# Stamped into the binary; see internal/version.
VERSION="${VERSION:-$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)}"

mkdir -p "$ROOT/.dev/gocache" "$ROOT/.dev/gomodcache" "$ROOT/bin"

run_logged build docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e CGO_ENABLED=0 \
  -e GOCACHE=/cache/go-build \
  -e GOMODCACHE=/cache/gomod \
  -v "$ROOT":/src -w /src \
  -v "$ROOT/.dev/gocache":/cache/go-build \
  -v "$ROOT/.dev/gomodcache":/cache/gomod \
  golang:1.26-alpine \
  go build -ldflags "-X github.com/voidgrid/voidgrid-secrets/internal/version.Version=$VERSION" -o bin/voidgrid-secrets ./cmd/voidgrid-secrets
exit $?
