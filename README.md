# voidgrid-secrets

If you've seen my backup project you've seen my explanation of how I'm using Claude for this. While this version is all Claude, I am reading the code and learning Go as I work on this. I wanted something way more simple but still secure for secrets manager than anything I could find so I started working on it. This is a homelab-centric secrets management project for use in my own lab. It is single user and hopefully dead simple to use. Some of the complexity that it has is because Docker doesn't have a [native injection path](https://github.com/docker/compose/pull/14230) as of yet. When it does, I'll refactor this.

voidegrid-secrets does have a real test suite, the encyrption should be solid, and the DB properly designed (I do know a little bit about both of those. If you want to use this then I advise, very strongly, to read the code before trusting it. I am not asking you to trust me at all as I am using Claude, for the love of God dig into the code yourself and understand before running it in your homelab. For all you know running this could get your fridge pregnant, turn your toaster into a Transformer, cause your signicant other to expect you to actually do the dishes, or summon Abraxas in the middle of your bathroom whilst you are showering and I wouldn't want you blaming me for any of that. And for the loved of the gods ***DO NOT*** expose this to the open Internet.

## Requirements

- Docker - the only thing needed to run, build, or develop this project.
- If you decide to ignore my warning and expose this to the internet then this is the bare minimum
  - A reverse proxy that terminates HTTPS in front of it (Caddy, Traefik,
  nginx): the app serves plain HTTP, and its session cookies require HTTPS
  except from networks you list in `VOIDGRID_HTTP_ALLOWED_NETS` (see
  [docs/deployment.md](docs/deployment.md#3-https-or-a-trusted-network)).
  - Again, do not fucking do this
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
  key, volumes, HTTPS or trusted networks, backup and restore, upgrading,
  restarts, environment variables, using secrets from other containers.
- [docs/first-steps.md](docs/first-steps.md) - add a secret, create a token,
  grant it, and use it from a container.
- [docs/authentication.md](docs/authentication.md) - the setup wizard,
  password + TOTP, OIDC (including the callback URL to register with your
  provider), account recovery and the break-glass `recover` command,
  sessions, and sign-in lockout.
- [docs/audit-log.md](docs/audit-log.md) - what's recorded, and the
  viewer at `/audit`.
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
consumers authenticate with scoped machine tokens (bearer tokens); the
web UI uses a password + TOTP or OIDC session for the one account.
`/api/v1/secrets/*` accepts either (a token only reaches what it's
granted); `/api/v1/env` (all of a token's secrets at once, used by
`voidgrid-secrets run` and the agent) is machine-token only;
`/api/v1/tokens` and `/api/v1/audit` are session only.

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
