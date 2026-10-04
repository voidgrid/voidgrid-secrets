# Deployment

Build: `make docker-build`, or `docker build -f deploy/docker/Dockerfile .`
from the repo root.

The image runs both the app and a single-node rqlite instance together,
supervised by s6-overlay. It's x86_64 only for now.

## First run

Generate the root encryption key before the first start - the service
refuses to start without it (deliberately: it won't silently generate a
new one if the file is just temporarily missing, which would be far worse
than refusing to start):

```
docker run --rm --entrypoint /usr/local/bin/voidgrid-secrets \
  -v voidgrid-root-key:/run/secrets \
  voidgrid-secrets keygen -path /run/secrets/voidgrid-root-key
```

**Back this volume up like you would any other secret material.** Losing
the root key makes every secret in the store permanently unrecoverable;
there is no recovery path other than restoring it from a backup.

Then run the container with that same volume mounted, plus a volume for
`/data` (where rqlite's data lives):

```
docker run -d --name voidgrid-secrets \
  -p 8443:8443 \
  -v voidgrid-data:/data \
  -v voidgrid-root-key:/run/secrets \
  voidgrid-secrets
```

See `../docker-compose.example.yml` for the same setup via compose,
including a sketch of how a consumer service pulls a secret via a machine
token into its own `.env`.

## Restarting

The container is designed to restart completely unattended: the root key
comes from the mounted volume (not typed in), and rqlite's data persists
on its own volume. No human interaction is required on restart as long as
both volumes are intact.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `VOIDGRID_LISTEN_ADDR` | `0.0.0.0:8443` | Address the API + web UI bind to |
| `VOIDGRID_RQLITE_ADDR` | `http://127.0.0.1:4001` | rqlite HTTP API (internal, same container) |
| `VOIDGRID_ROOT_KEY_PATH` | `/run/secrets/voidgrid-root-key` | Root encryption key file |
| `RQLITE_DATA_DIR` | `/data/rqlite` | rqlite's on-disk data directory |

The app has no TLS of its own; put a reverse proxy (Caddy, Traefik, nginx)
in front of it for HTTPS. Session cookies are marked `Secure`, so the web
UI's login will not work over plain HTTP from a real browser - this is
intentional, not a bug, and matches how most homelab reverse-proxy setups
already terminate TLS before traffic reaches application containers.
