#!/bin/sh
# Runs a local rqlite + voidgrid-secrets dev loop: builds the binary,
# starts a throwaway single-node rqlited, generates a root key if one
# doesn't already exist, and runs the app in the foreground. Ctrl-C stops
# both. State lives under ./.dev/ (gitignored), not in /tmp or $HOME.
set -eu

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
DEV_DIR="$ROOT_DIR/.dev"
mkdir -p "$DEV_DIR/rqlite-data"

cleanup() {
    [ -n "${RQLITED_PID:-}" ] && kill "$RQLITED_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

go build -o "$ROOT_DIR/bin/voidgrid-secrets" "$ROOT_DIR/cmd/voidgrid-secrets"

rqlited -fk -http-addr 127.0.0.1:4001 -raft-addr 127.0.0.1:4002 "$DEV_DIR/rqlite-data" \
    > "$DEV_DIR/rqlite.log" 2>&1 &
RQLITED_PID=$!

if [ ! -f "$DEV_DIR/root.key" ]; then
    "$ROOT_DIR/bin/voidgrid-secrets" keygen -path "$DEV_DIR/root.key"
fi

until curl -sf -o /dev/null http://127.0.0.1:4001/readyz 2>/dev/null; do
    sleep 0.2
done

VOIDGRID_RQLITE_ADDR=http://127.0.0.1:4001 \
VOIDGRID_LISTEN_ADDR=127.0.0.1:8443 \
VOIDGRID_ROOT_KEY_PATH="$DEV_DIR/root.key" \
    "$ROOT_DIR/bin/voidgrid-secrets"
