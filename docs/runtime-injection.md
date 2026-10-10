# Injecting secrets at runtime

`voidgrid-secrets run` starts another container's real command with its
secrets already in place: it fetches every secret a machine token may
read, puts them into the environment (or into files on an in-memory
mount), then replaces itself with the real command. The values are never
written to disk and never appear in `docker inspect`.

```
voidgrid-secrets run [--url URL] [--token-file PATH] [--files DIR] [--timeout 30s] -- command [args...]
```

If the consuming image reads its secrets from files (`*_FILE` variables),
[agent mode](#agent-mode-no-wrapper) avoids wrapping it at all: one
sidecar keeps every consumer's secrets as files on a shared in-memory
volume, and picks up changed values without a restart.

Why not compose `environment:` or a `.env` file? Anything set there is
resolved on the host and stored in the container's configuration on disk,
readable by anyone who can run `docker inspect`. `run` injects inside the
container, at process start, so only the process itself ever holds the
values.

## 1. Create a token and grant it secrets

In the web UI, go to tokens, create a token for the service (it's shown
once), then open it (the link under the new token, or click its id or
description in the list) and tick each secret that service needs. A token
starts with no grants, and a token with none reads nothing. Each grant has
an environment variable name: set one explicitly (e.g. `POSTGRES_PASSWORD`)
or leave it blank to derive it from the secret's name (`db-password`
becomes `DB_PASSWORD`). A token can't have two secrets under the same name.
The token's page lists every name it exposes.

Give each service its own token, scoped to just its secrets.

## 2. Get the binary into the container

The binary is fully static, so it runs in any linux/amd64 image, including
distroless and scratch images. Either:

- **In your own Dockerfile:**

  ```
  COPY --from=ghcr.io/voidgrid/voidgrid-secrets:beta /usr/local/bin/voidgrid-secrets /usr/local/bin/voidgrid-secrets
  ```

- **Without building an image**, with a one-shot compose service that
  copies it into a shared volume (see `examples/docker-compose.yml`):

  ```yaml
  voidgrid-secrets-bin:
    image: ghcr.io/voidgrid/voidgrid-secrets:beta
    entrypoint: ["cp", "/usr/local/bin/voidgrid-secrets", "/export/voidgrid-secrets"]
    volumes:
      - voidgrid-bin:/export
  ```

  and in the consuming service:

  ```yaml
    depends_on:
      voidgrid-secrets-bin:
        condition: service_completed_successfully
    volumes:
      - voidgrid-bin:/opt/voidgrid:ro
  ```

## 3. Wrap the service's command

Set `run` as the entrypoint and put the image's **original** entrypoint
and command after `--` - Docker doesn't chain entrypoints, so they have to
be restated. Give it the token as a Docker secret (mounted at
`/run/secrets/voidgrid-token`, the default location) and the server's URL:

```yaml
  myapp:
    image: example/myapp:1.2
    depends_on:
      voidgrid-secrets-bin:
        condition: service_completed_successfully
    environment:
      VOIDGRID_URL: http://voidgrid-secrets:8780
    secrets:
      - voidgrid-token
    volumes:
      - voidgrid-bin:/opt/voidgrid:ro
    entrypoint: ["/opt/voidgrid/voidgrid-secrets", "run", "--"]
    command: ["/original/entrypoint", "--original-args"]

secrets:
  voidgrid-token:
    file: ./myapp-voidgrid-token
```

The token file must be readable by the user the container runs as.

### File mode for `*_FILE` images

Many images (Postgres, MariaDB, and others) read secrets from a file named
in a `*_FILE` variable. With `--files DIR`, each secret is written to
`DIR/<NAME>` (mode 0400) and `NAME_FILE` is set to its path instead of
`NAME` being set to the value. `DIR` must be an in-memory mount (tmpfs);
`run` refuses to start - before fetching anything - if it isn't.

```yaml
  postgres:
    image: postgres:17
    depends_on:
      voidgrid-secrets-bin:
        condition: service_completed_successfully
    environment:
      VOIDGRID_URL: http://voidgrid-secrets:8780
    secrets:
      - voidgrid-token
    volumes:
      - voidgrid-bin:/opt/voidgrid:ro
    tmpfs:
      - /run/voidgrid
    entrypoint: ["/opt/voidgrid/voidgrid-secrets", "run", "--files", "/run/voidgrid", "--", "docker-entrypoint.sh"]
    command: ["postgres"]
```

With the token granted `db-password` under the name `POSTGRES_PASSWORD`,
Postgres sees `POSTGRES_PASSWORD_FILE=/run/voidgrid/POSTGRES_PASSWORD`. If
the container runs as a non-root user, give the mount that user's
ownership, e.g. `/run/voidgrid:uid=1000,gid=1000,mode=0700`.

## Behavior

- **Startup order:** `run` retries for up to `--timeout` (30 seconds by
  default) while the server is unreachable or still starting, so it copes
  with compose start order. A rejected or revoked token fails immediately.
- **Fails closed:** if it can't get the secrets, it exits non-zero and the
  real command never starts. Restart policies retry it. That includes a
  token with no grants: it fails with a message pointing at the token's
  page, instead of starting the command without its secrets.
- **Says what it did:** before starting the command it prints the names
  (never the values) of the variables it injected to stderr.
- **Read once:** secrets are read at start. Restart the container to pick
  up a changed value.
- **Clean environment:** `VOIDGRID_TOKEN`, `VOIDGRID_TOKEN_FILE` and
  `VOIDGRID_URL` are removed before the real command starts. If a secret
  has the same name as an existing variable, the secret wins and the name
  (never the value) is noted on stderr.
- **Same process:** the real command replaces `run` (it keeps the same
  PID), so signals and exit codes behave exactly as if it had been started
  directly.
- **Audited:** every value handed out is recorded in the audit log as a
  reveal by that token.

| Setting | Flag | Environment variable | Default |
|---|---|---|---|
| Server URL | `--url` | `VOIDGRID_URL` | none (required) |
| Token file | `--token-file` | `VOIDGRID_TOKEN_FILE` | `/run/secrets/voidgrid-token` |
| Token value | | `VOIDGRID_TOKEN` | used only if no token file exists |
| File mode | `--files DIR` | | off (environment variables) |
| Retry window | `--timeout` | | `30s` |

Prefer a token file over `VOIDGRID_TOKEN`: a variable set in compose ends
up in `docker inspect`, which is exactly what this avoids for the secrets
themselves.

## Limits

- **The token itself still has to reach the container.** As a Docker
  secret it's a file on the host's disk. Scope each token to read-only on
  just that service's secrets, so a leaked token exposes as little as
  possible, and revoke it from the tokens page if it leaks.
- **Process memory is readable locally.** Root, or the same user inside
  the container, can read a running process's environment through
  `/proc`. That's true of every tool that works this way.
- **Plain HTTP on the Docker network.** Inside one compose project,
  `http://voidgrid-secrets:8780` never leaves the host. Across hosts, use
  the HTTPS address behind your reverse proxy.

## Agent mode: no wrapper

`voidgrid-secrets agent` runs as its own container and keeps each
consumer's secrets as files on a shared in-memory volume. The consumer
needs no wrapper, no copy of the binary and no entrypoint changes - only
a volume mount and the `*_FILE` variables its image already supports.

```
voidgrid-secrets agent --url URL --out DIR --target NAME=TOKEN_FILE,gid=GID [--target ...] [--interval 1m] [--timeout 30s]
```

Each `--target` is one consumer: the subdirectory its files go in
(`DIR/NAME`), the token whose grants decide what goes there, and the group
allowed to read them. Give every consumer its own token, exactly as with
`run`; the agent only carries them, it never widens what a token can read.

### How the files are protected

- The volume is tmpfs, so nothing reaches disk. The agent refuses to
  start if `--out` isn't an in-memory filesystem.
- Each consumer mounts only its own subdirectory (`subpath`), so it can't
  see any other consumer's files.
- Files are mode 0440 and owned by the target's group; the subdirectory
  is 0750. The agent runs unprivileged (UID 1000) and can only give files
  to a group it's a member of, so every target's GID goes in the agent's
  `group_add`. The consumer reads its files as that group - its own
  primary group, or one added with `group_add`. Consumers running as root
  can read them regardless.
- Values are replaced by writing a new file and renaming it over the old
  one, so the application never reads a partial value.

### Example

A Postgres consumer (the official image runs as UID/GID 999):

```yaml
services:
  voidgrid-agent:
    image: ghcr.io/voidgrid/voidgrid-secrets:beta
    entrypoint: ["/usr/local/bin/voidgrid-secrets", "agent"]
    command:
      - --url=http://voidgrid-secrets:8780
      - --out=/out
      - --target=postgres=/run/secrets/postgres-token,gid=999
    group_add: ["999"]
    secrets:
      - postgres-token
    volumes:
      - voidgrid-out:/out
    healthcheck:
      test: ["CMD", "test", "-f", "/tmp/voidgrid-agent-ready"]
      interval: 5s
    restart: unless-stopped

  postgres:
    image: postgres:17
    depends_on:
      voidgrid-agent:
        condition: service_healthy
    environment:
      POSTGRES_PASSWORD_FILE: /run/voidgrid/POSTGRES_PASSWORD
    volumes:
      - type: volume
        source: voidgrid-out
        target: /run/voidgrid
        read_only: true
        volume:
          subpath: postgres

volumes:
  voidgrid-out:
    driver_opts:
      type: tmpfs
      device: tmpfs
      o: "size=1m,uid=1000,gid=1000,mode=0700"

secrets:
  postgres-token:
    file: ./postgres-voidgrid-token
```

For a consumer whose image runs as a different user, add the target's
GID to that consumer's `group_add` too. Token files must be readable by
the agent (UID 1000).

### Agent behavior

- **Startup:** the agent checks its configuration first (in-memory
  `--out`, membership of every target's group, readable token files) and
  exits without contacting the server if any check fails. It then writes
  every target, retrying for up to `--timeout` while the server is
  unreachable or starting; a rejected token fails startup. Once every
  target is written it creates `/tmp/voidgrid-agent-ready`, which the
  healthcheck above waits for - so `service_healthy` means the files are
  there.
- **Changes:** every `--interval` (1 minute by default) it asks the
  server whether anything changed. Unchanged checks return no values and
  add nothing to the audit log; a changed value is rewritten, a newly
  granted secret appears, and a file whose grant is gone is removed. Every
  value actually handed out is audited as a reveal by that target's
  token, as with `run`.
- **Picking up a change:** the agent replaces the file; it doesn't
  restart or signal the consumer (that would need the Docker socket).
  Applications that read the file once at startup need a restart to see
  the new value.
- **Server down:** the last values stay in place and the outage is
  logged once.
- **Token revoked or expired:** that target's files are removed, and come
  back if access is restored.
- The token file is re-read on every check, so replacing it takes effect
  without restarting the agent.
- Logs name targets and variable names only, never values.

### Agent limits

- Needs Docker Engine 26.0 or newer, for mounting a volume's subdirectory
  (`subpath`).
- The tokens still reach the agent as files on the host's disk, as with
  `run`.
- Files only: an image that only reads plain environment variables still
  needs `run`.
