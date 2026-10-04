#!/usr/bin/env bash
# Docker-first test: runs `go test -race ./...` inside the official Go
# image. Uses the Debian-based (not alpine) image because -race needs
# CGO, which needs a C toolchain that alpine's Go image doesn't ship.
# Integration tests that need a real rqlited binary skip themselves
# (exec.LookPath check) since this image doesn't have one either -
# that's a known gap, not a silent false pass - the skip count is printed.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/_run.sh"

mkdir -p "$ROOT/.dev/gocache" "$ROOT/.dev/gomodcache"

run_logged test docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e CGO_ENABLED=1 \
  -e GOCACHE=/cache/go-build \
  -e GOMODCACHE=/cache/gomod \
  -v "$ROOT":/src -w /src \
  -v "$ROOT/.dev/gocache":/cache/go-build \
  -v "$ROOT/.dev/gomodcache":/cache/gomod \
  golang:1.26 \
  go test -race -v ./...
status=$?

skipped=$(grep -c '^--- SKIP' "$ROOT/.dev/logs/test.log" || true)
if [ "$skipped" -gt 0 ]; then
  echo "note: $skipped test(s) skipped (likely rqlited not available in this image)"
fi

exit "$status"
