#!/bin/sh
# Runs a local voidgrid-secrets dev loop: builds the binary, generates a
# root key if one doesn't already exist, and runs the app in the foreground
# against a SQLite file. State lives under ./.dev/ (gitignored), not in /tmp
# or $HOME.
set -eu

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
DEV_DIR="$ROOT_DIR/.dev"
mkdir -p "$DEV_DIR"

go build -o "$ROOT_DIR/bin/voidgrid-secrets" "$ROOT_DIR/cmd/voidgrid-secrets"

if [ ! -f "$DEV_DIR/root.key" ]; then
    "$ROOT_DIR/bin/voidgrid-secrets" keygen -path "$DEV_DIR/root.key"
fi

VOIDGRID_DB_PATH="$DEV_DIR/voidgrid.db" \
VOIDGRID_LISTEN_ADDR=127.0.0.1:8780 \
VOIDGRID_ROOT_KEY_PATH="$DEV_DIR/root.key" \
    "$ROOT_DIR/bin/voidgrid-secrets"
