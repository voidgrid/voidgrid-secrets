# Injecting secrets at runtime

`voidgrid-secrets run` starts another container's real command with its
secrets already in place: it fetches every secret a machine token may
read, puts them into the environment (or into files on an in-memory
mount), then replaces itself with the real command. The values are never
written to disk and never appear in `docker inspect`.

```
voidgrid-secrets run [--url URL] [--token-file PATH] [--files DIR] [--timeout 30s] -- command [args...]
```

Why not compose `environment:` or a `.env` file? Anything set there is
resolved on the host and stored in the container's configuration on disk,
readable by anyone who can run `docker inspect`. `run` injects inside the
container, at process start, so only the process itself ever holds the
values.

## 1. Create a token and grant it secrets

In the web UI, go to admin > tokens, create a token for the service (it's
shown once), and grant it **read** on each secret that service needs. Each
grant has an environment variable name: set one explicitly (e.g.
`POSTGRES_PASSWORD`) or leave it blank to derive it from the secret's name
(`db-password` becomes `DB_PASSWORD`). A token can't have two secrets
under the same name. The token's page lists every name it exposes.

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
      VOIDGRID_URL: http://voidgrid-secrets:8443
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
      VOIDGRID_URL: http://voidgrid-secrets:8443
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
  real command never starts. Restart policies retry it.
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
  possible, and revoke it from admin > tokens if it leaks.
- **Process memory is readable locally.** Root, or the same user inside
  the container, can read a running process's environment through
  `/proc`. That's true of every tool that works this way.
- **Plain HTTP on the Docker network.** Inside one compose project,
  `http://voidgrid-secrets:8443` never leaves the host. Across hosts, use
  the HTTPS address behind your reverse proxy.
- **Per-secret grants only.** A token's group grants aren't used by `run`.
