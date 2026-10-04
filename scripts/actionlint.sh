#!/usr/bin/env bash
# Docker-first lint for GitHub Actions workflows.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/_run.sh"

run_logged actionlint docker run --rm \
  -v "$ROOT":/repo -w /repo \
  rhysd/actionlint:latest \
  -color .github/workflows/release.yml
exit $?
