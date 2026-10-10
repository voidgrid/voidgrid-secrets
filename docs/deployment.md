# Deployment

voidgrid-secrets ships as one container image,
`ghcr.io/voidgrid/voidgrid-secrets`. It runs the app and a single-node
rqlite database together under s6-overlay. The image is x86_64 only for
now. Pin a specific version tag for anything you rely on.

The container runs unprivileged, as UID/GID 1000 - every process,
including the s6 supervisor. Nothing in it needs root.

Something not working? See [troubleshooting.md](troubleshooting.md).

## 1. Generate the root key

The root encryption key encrypts every secret. The service refuses to
start without it, and `keygen` refuses to overwrite an existing key, so a
missing file never silently becomes a new key.

With compose (see `examples/docker-compose.yml`):

```
docker compose -f examples/docker-compose.yml run --rm --entrypoint /usr/local/bin/voidgrid-secrets voidgrid-secrets keygen -path /run/secrets/voidgrid-root-key
```

Or with plain `docker run`:

```
docker run --rm --entrypoint /usr/local/bin/voidgrid-secrets -v voidgrid-root-key:/run/secrets ghcr.io/voidgrid/voidgrid-secrets:beta keygen -path /run/secrets/voidgrid-root-key
```

**Back up the `voidgrid-root-key` volume like any other secret
material.** Losing the key makes every stored secret permanently
unrecoverable; there is no recovery path other than restoring it.

If you supply the key file yourself instead (for example as a mounted
Docker secret), it must be readable by UID 1000 and must not be
accessible to group or others (mode `0600`) - the service refuses to load
a key file with looser permissions.

## 2. Run it

```
docker compose -f examples/docker-compose.yml up -d
```

Or:

```
docker run -d --name voidgrid-secrets --user 1000:1000 -p 8780:8780 -v voidgrid-data:/data -v voidgrid-root-key:/run/secrets ghcr.io/voidgrid/voidgrid-secrets:beta
```

`/data` holds rqlite's database; `/run/secrets` holds the root key. Back
up both volumes.

## 3. HTTPS, or a trusted network

The app serves plain HTTP on port 8780 (not TLS, despite what the port
number might suggest) and has no TLS of its own. Sign-in cookies are
marked `Secure`, which browsers drop over plain HTTP, so by default sign-in
works only over HTTPS: put a reverse proxy (Caddy, Traefik, nginx) in front
of it and have it send `X-Forwarded-Proto: https`.

For a homelab you can instead allow plain-HTTP sign-in from your own
networks. Set `VOIDGRID_HTTP_ALLOWED_NETS` to a comma-separated list of
CIDRs - for example your LAN and Tailscale - in the `.env` file next to
your compose file (the example compose file passes it through):

```
VOIDGRID_HTTP_ALLOWED_NETS=192.168.1.0/24,100.64.0.0/10,fd7a:115c:a1e0::/48
```

(`100.64.0.0/10` and `fd7a:115c:a1e0::/48` are Tailscale's IPv4 and IPv6
ranges.) How it works:

- It is empty by default, so nothing changes until you set it.
- It matches the **TCP peer address** of the connection. `X-Forwarded-For`
  is never trusted, since a spoofed header could otherwise switch `Secure`
  off.
- From a listed network, plain HTTP works: `Secure` is dropped from the
  cookies. HTTPS (direct, or `X-Forwarded-Proto: https` from your proxy)
  always keeps `Secure`.
- From anywhere else, sign-in, recovery and setup over plain HTTP are
  refused with a "use HTTPS" message. Machine-token API calls
  (`/api/v1/env`, `/api/v1/secrets`) are not affected.
- Behind a reverse proxy the peer address is the proxy's, not the
  browser's. That is fine when the proxy speaks HTTPS to browsers; if
  you want to allow plain HTTP through it, list the proxy's network.
- With a published Docker port, connections made from the Docker host
  itself appear to come from the compose network's gateway (for example
  `172.19.0.1`, measured), not `127.0.0.1`. Add `172.16.0.0/12`, which covers
  Docker's default ranges, if you sign in from the host.

The published port in the example compose file is open on all interfaces,
which this setup needs. If a proxy on the same host is the only client,
use the commented `127.0.0.1:8780:8780` line there instead.

## 4. Finish first-run setup

Until setup is complete, the server prints a one-time **setup token** to
its log at every start, and the setup wizard refuses every step without
it - so only someone who can read the container's log can create the
account or configure OIDC:

```
docker compose logs voidgrid-secrets | grep 'setup token'
```

(Run compose commands from the directory with your compose file, or add
`-f path/to/docker-compose.yml`. With plain `docker run` as above, use
`docker logs voidgrid-secrets` instead. Compose names containers
`<project>-voidgrid-secrets-1`, so `docker logs voidgrid-secrets` does not
find a compose-started container.)

Open `/setup`, enter the token, and follow the wizard - see
[authentication.md](authentication.md). The token lives only in the
running process: a restart prints a new one, and once setup is complete
none is generated.

## Locked out

If you've lost your password or authenticator, use a recovery code at
`/recover`. If the recovery codes are gone too, run
`docker compose exec voidgrid-secrets voidgrid-secrets recover` for a
one-time code - see [authentication.md](authentication.md#recovery).

## Backup and restore

The database lives in the data volume and is encrypted with the key in the
root-key volume. **Back up both together, from the same moment**: a
database is useless without the key it was written under.

Pause the container so nothing is writing, copy both volumes, and resume.
First find the real volume names (compose prefixes them with the project
name):

```
docker volume ls | grep voidgrid
```

Then, substituting those names:

```
docker compose pause voidgrid-secrets; docker run --rm -v DATA_VOLUME:/v:ro -v "$PWD":/backup alpine tar czf /backup/voidgrid-data.tgz -C /v .; docker run --rm -v KEY_VOLUME:/v:ro -v "$PWD":/backup alpine tar czf /backup/voidgrid-root-key.tgz -C /v .; docker compose unpause voidgrid-secrets
```

(`docker compose stop` / `start` works the same way if you prefer a full
stop.) The key archive is as sensitive as the secrets themselves: keep it
somewhere you trust, and consider storing it apart from the data archive.

To restore, stop the container, empty and refill both volumes, and start
it:

```
docker compose stop voidgrid-secrets; docker run --rm -v DATA_VOLUME:/v -v "$PWD":/backup alpine sh -c 'rm -rf /v/* /v/.[!.]* ; tar xzf /backup/voidgrid-data.tgz -C /v'; docker run --rm -v KEY_VOLUME:/v -v "$PWD":/backup alpine sh -c 'rm -rf /v/* /v/.[!.]* ; tar xzf /backup/voidgrid-root-key.tgz -C /v'; docker compose start voidgrid-secrets
```

This deletes what is currently in those volumes, so only run it when you
mean to replace them. Restore the data and the key from the same backup.

## Upgrading

1. Back up (above).
2. Change the image tag in your compose file (or keep `:beta`), then:

```
docker compose pull voidgrid-secrets; docker compose up -d voidgrid-secrets
```

Database migrations run automatically at start, so there is nothing else
to do. They only go forward: to go back to an older version, restore the
backup you took first. Check the release notes for changes that need your
attention, such as a changed port or setting.

Upgrading from `v0.1.0-beta.1`: the default port changed from 8443 to
8780. Update the published port in your compose file and any reverse
proxy, and `VOIDGRID_URL` in consumers.

## Health

The image has a built-in healthcheck: it asks the app for
`/api/v1/setup/status`, which only answers once the app and its database
are both up. `docker ps` shows `healthy`, and other services can wait for
it with `depends_on: voidgrid-secrets: condition: service_healthy`.

## Restarting

The container restarts fully unattended: the root key comes from its
volume and the database persists on its own. If OIDC is configured and the
identity provider is unreachable when the container starts, the service
still starts; OIDC sign-in stays unavailable until the next restart with
the provider reachable, and recovery-code login keeps working meanwhile.

## Environment variables

The first three are set in the image; you normally don't need to change
them. `VOIDGRID_HTTP_ALLOWED_NETS` is yours to set.

| Variable | Default in the image | Purpose |
|---|---|---|
| `VOIDGRID_LISTEN_ADDR` | `0.0.0.0:8780` | Address the API + web UI bind to |
| `VOIDGRID_RQLITE_ADDR` | `http://127.0.0.1:4001` | rqlite HTTP API (internal, same container) |
| `VOIDGRID_ROOT_KEY_PATH` | `/run/secrets/voidgrid-root-key` | Root encryption key file |
| `VOIDGRID_HTTP_ALLOWED_NETS` | empty | Comma-separated CIDRs allowed to sign in over plain HTTP; see [section 3](#3-https-or-a-trusted-network) |
| `RQLITE_DATA_DIR` | `/data/rqlite` | rqlite's on-disk data directory |

## Using secrets from other containers

Create a machine token in the web UI (tokens) for each consuming service
and grant it read on just the secrets it needs. The token is shown once.

The recommended way to use it is `voidgrid-secrets run`, which wraps the
consuming container's command and injects every granted secret at
startup, as environment variables or as files on an in-memory mount,
without writing them to disk or exposing them in `docker inspect`. For
images that read secrets from files (`*_FILE` variables), agent mode
needs no wrapper at all: a sidecar keeps each consumer's secrets as files
on a shared in-memory volume and updates them when they change. See
[runtime-injection.md](runtime-injection.md) and the examples in
`examples/docker-compose.yml`. For a walk through adding a secret, making
a token and granting it, see [first-steps.md](first-steps.md).

Tokens can also call the API directly: `GET /api/v1/env` returns every
secret the token may read with its environment variable name, and
`GET /api/v1/secrets/{id}` returns one secret, both with
`Authorization: Bearer <token>`.

The full API is documented by the running instance itself: interactive
docs at `/docs`, the OpenAPI 3.1 spec at `/openapi.json`.
