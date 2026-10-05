#!/usr/bin/env bash
# Live tests: these hit real external services (a real OIDC provider), so
# they sit behind the `live` build tag and never run in `make test` or the
# image build. Values come from .env at the repo root - copy env.example
# and fill it in. Missing .env is an error; values still set to CHANGEME
# skip the run. Variable values are never printed.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/_run.sh"

REQUIRED=(LIVE_OIDC_ISSUER LIVE_OIDC_CLIENT_ID LIVE_OIDC_REDIRECT_URI)

banner() {
  printf '\n==================================================\n %s\n==================================================\n\n' "$*"
}

if [ ! -f "$ROOT/.env" ]; then
  banner "ERROR: no .env at the repo root - copy env.example to .env and fill it in"
  exit 1
fi

set -a
# shellcheck disable=SC1091
. "$ROOT/.env"
set +a

missing=()
for name in "${REQUIRED[@]}"; do
  if [ "${!name:-CHANGEME}" = "CHANGEME" ]; then
    missing+=("$name")
  fi
done
if [ "${#missing[@]}" -gt 0 ]; then
  banner "SKIPPING live tests - still CHANGEME (or unset) in .env: ${missing[*]}"
  exit 0
fi

mkdir -p "$ROOT/.dev/gocache" "$ROOT/.dev/gomodcache"

envargs=()
for name in "${REQUIRED[@]}"; do
  envargs+=(-e "$name")
done

run_logged live-test docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e GOCACHE=/cache/go-build \
  -e GOMODCACHE=/cache/gomod \
  "${envargs[@]}" \
  -v "$ROOT":/src -w /src \
  -v "$ROOT/.dev/gocache":/cache/go-build \
  -v "$ROOT/.dev/gomodcache":/cache/gomod \
  golang:1.26-alpine \
  go test -tags live -count=1 -v ./internal/auth/oidc/
exit $?
