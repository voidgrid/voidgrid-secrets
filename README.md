# voidgrid-secrets

<!-- operator's framing goes here -->

## Requirements

- Docker (the only thing needed to build, run, or develop this project -
  see "Development" below)

## Quick start

```
docker compose -f deploy/docker-compose.example.yml run --rm \
  --entrypoint /usr/local/bin/voidgrid-secrets voidgrid-secrets \
  keygen -path /run/secrets/voidgrid-root-key
docker compose -f deploy/docker-compose.example.yml up -d
```

The first command generates the root encryption key. **Back up the
`voidgrid-root-key` volume it writes to like you would any other secret
material** — losing it makes every secret in the store permanently
unrecoverable, with no other recovery path.

See `deploy/docker-compose.example.yml` for the full example, including a
sketch of how a consumer service pulls a secret into its own `.env` via a
machine token, and `deploy/docker/README.md` for the equivalent plain
`docker run` commands.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `VOIDGRID_LISTEN_ADDR` | `0.0.0.0:8443` | Address the API + web UI bind to |
| `VOIDGRID_RQLITE_ADDR` | `http://127.0.0.1:4001` | rqlite HTTP API (internal, same container) |
| `VOIDGRID_ROOT_KEY_PATH` | `/run/secrets/voidgrid-root-key` | Root encryption key file |
| `RQLITE_DATA_DIR` | `/data/rqlite` | rqlite's on-disk data directory |

The app has no TLS of its own; put a reverse proxy (Caddy, Traefik, nginx)
in front of it for HTTPS. Session cookies are marked `Secure`, so the web
UI's login will not work over plain HTTP from a real browser — this is
intentional, matching how most homelab reverse-proxy setups already
terminate TLS before traffic reaches application containers.

## API

The API is spec-first (via `huma`), with an OpenAPI 3.1 spec and docs UI
served at `/docs` on a running instance. Automated consumers (the
docker/`.env` use case) authenticate with scoped, admin-issued bearer
tokens; the web UI uses password+TOTP or OIDC sessions. `/api/v1/secrets/*`
accepts either; `/api/v1/admin/*` is session+admin-only.

## Development

Docker-first: there is no local toolchain to install. Each `make` target
runs its tool inside the matching official container via a small wrapper
script under `scripts/`:

| Command | Runs |
|---|---|
| `make build` | Compiles the binary (`scripts/build.sh`) |
| `make vet` | `go vet` (`scripts/vet.sh`) |
| `make test` | `go test -race ./...` (`scripts/test.sh`) |
| `make lint` | golangci-lint (`scripts/lint.sh`) |
| `make fmt` | gofumpt (`scripts/fmt.sh`) |
| `make run` | Builds, then runs the binary directly |
| `make docker-build` | Builds the full container image |
| `make dev` | Local rqlite + app dev loop (`scripts/dev.sh`) |

The production `Dockerfile`'s build stage runs `go vet` and
`go test -race` itself, with a real `rqlited` binary available, so a
failing test fails the image build — not just a separate CI step.

Build/test/lint output is logged in full under `.dev/logs/` (gitignored);
only a short pass/fail result prints to the terminal.
