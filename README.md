# voidgrid-secrets

<!-- operator's framing goes here -->

## Requirements

- Docker - the only thing needed to run, build, or develop this project.
- A reverse proxy that terminates HTTPS in front of it (Caddy, Traefik,
  nginx): the app serves plain HTTP and its session cookies require HTTPS.
- Optionally, an OIDC identity provider (e.g. Pocket ID) if you'd rather
  not use password + TOTP sign-in.

## Quick start

The image is published at `ghcr.io/voidgrid/voidgrid-secrets` and runs
unprivileged as UID/GID 1000.

1. Generate the root encryption key (once):

   ```
   docker compose -f examples/docker-compose.yml run --rm --entrypoint /usr/local/bin/voidgrid-secrets voidgrid-secrets keygen -path /run/secrets/voidgrid-root-key
   ```

   **Back up the `voidgrid-root-key` volume like any other secret
   material** - losing the key makes every stored secret permanently
   unrecoverable.

2. Start it:

   ```
   docker compose -f examples/docker-compose.yml up -d
   ```

3. Get the one-time setup token from the log:

   ```
   docker compose -f examples/docker-compose.yml logs voidgrid-secrets | grep 'setup token'
   ```

4. Open `/setup`, enter the token, and complete the first-run wizard.

## Documentation

- [docs/deployment.md](docs/deployment.md) - running the image, the root
  key, volumes, HTTPS, restarts, environment variables, using secrets from
  other containers.
- [docs/authentication.md](docs/authentication.md) - the setup wizard,
  password + TOTP, OIDC (including the callback URL to register with your
  provider), recovery codes, sessions, sign-in lockout, and what admins
  can see.
- [docs/audit-log.md](docs/audit-log.md) - what's recorded, and the
  viewer at `/admin/audit`.
- [docs/runtime-injection.md](docs/runtime-injection.md) -
  `voidgrid-secrets run`: give another container its secrets at startup,
  as environment variables or tmpfs files, without writing them to disk;
  and `voidgrid-secrets agent`: a sidecar that keeps consumers' secrets
  as files on a shared in-memory volume, with no wrapper.
- [examples/docker-compose.yml](examples/docker-compose.yml) - a complete
  compose example, including consumer services that get their secrets via
  `voidgrid-secrets run` and via the agent.

## API

The API is spec-first (via `huma`): a running instance serves interactive
docs at `/docs` and the OpenAPI 3.1 spec at `/openapi.json`. Automated
consumers authenticate with scoped, admin-issued machine tokens (bearer
tokens); the web UI uses password + TOTP or OIDC sessions.
`/api/v1/secrets/*` accepts either; `/api/v1/env` (all of a token's
secrets at once, used by `voidgrid-secrets run`) is machine-token only;
`/api/v1/admin/*` is session-and-admin only.

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
| `make lint-workflows` | actionlint on the GitHub Actions workflows (`scripts/actionlint.sh`) |
| `make fmt` | gofumpt (`scripts/fmt.sh`) |
| `make live-test` | Live tests against a real OIDC provider (`scripts/live-test.sh`) |
| `make run` | Builds, then runs the binary directly |
| `make docker-build` | Builds the full container image |
| `make dev` | Local rqlite + app dev loop (`scripts/dev.sh`) |

Tests gate the image: the Dockerfile's build stage runs `go vet` and
`go test -race` against a real `rqlited`, so a failing test fails the
build. `make test` runs the same suite in the same toolchain (the
Dockerfile's `testenv` stage, built and cached on first use), including
the database integration tests.

`make live-test` reads its settings from a `.env` at the repo root - copy
`env.example` and fill it in. It errors if `.env` is missing and skips if
anything is still `CHANGEME`.

Build/test/lint output is logged in full under `.dev/logs/` (gitignored);
only a short pass/fail result prints to the terminal.
