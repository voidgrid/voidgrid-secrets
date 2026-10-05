# Deployment

voidgrid-secrets ships as one container image,
`ghcr.io/voidgrid/voidgrid-secrets`. It runs the app and a single-node
rqlite database together under s6-overlay. The image is x86_64 only for
now. Pin a specific version tag for anything you rely on.

The container runs unprivileged, as UID/GID 1000 - every process,
including the s6 supervisor. Nothing in it needs root.

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
docker run -d --name voidgrid-secrets --user 1000:1000 -p 8443:8443 -v voidgrid-data:/data -v voidgrid-root-key:/run/secrets ghcr.io/voidgrid/voidgrid-secrets:beta
```

`/data` holds rqlite's database; `/run/secrets` holds the root key. Back
up both volumes.

## 3. Put it behind HTTPS

The app serves plain HTTP on port 8443 and has no TLS of its own. Put a
reverse proxy (Caddy, Traefik, nginx) in front of it. Session cookies are
marked `Secure`, so web login only works over HTTPS.

## 4. Finish first-run setup before exposing it

Until the setup wizard has been completed, **anyone who can reach the
instance can complete it and become the admin**. Do it before the
instance is reachable from anywhere you don't trust - see
[authentication.md](authentication.md).

## Restarting

The container restarts fully unattended: the root key comes from its
volume and the database persists on its own. If OIDC is configured and the
identity provider is unreachable when the container starts, the service
still starts; OIDC sign-in stays unavailable until the next restart with
the provider reachable, and recovery-code login keeps working meanwhile.

## Environment variables

These are set in the image; you normally don't need to change them.

| Variable | Default in the image | Purpose |
|---|---|---|
| `VOIDGRID_LISTEN_ADDR` | `0.0.0.0:8443` | Address the API + web UI bind to |
| `VOIDGRID_RQLITE_ADDR` | `http://127.0.0.1:4001` | rqlite HTTP API (internal, same container) |
| `VOIDGRID_ROOT_KEY_PATH` | `/run/secrets/voidgrid-root-key` | Root encryption key file |
| `RQLITE_DATA_DIR` | `/data/rqlite` | rqlite's on-disk data directory |

## Using secrets from other containers

Create a machine token in the web UI (admin > tokens) for each consuming
service and grant it read on just the secrets it needs. The token is
shown once.

The recommended way to use it is `voidgrid-secrets run`, which wraps the
consuming container's command and injects every granted secret at
startup, as environment variables or as files on an in-memory mount,
without writing them to disk or exposing them in `docker inspect`. See
[runtime-injection.md](runtime-injection.md) and the example in
`examples/docker-compose.yml`.

Tokens can also call the API directly: `GET /api/v1/env` returns every
secret the token may read with its environment variable name, and
`GET /api/v1/secrets/{id}` returns one secret, both with
`Authorization: Bearer <token>`.

The full API is documented by the running instance itself: interactive
docs at `/docs`, the OpenAPI 3.1 spec at `/openapi.json`.
