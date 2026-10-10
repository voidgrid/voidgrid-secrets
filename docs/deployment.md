# Deployment

voidgrid-secrets ships as one container image,
`ghcr.io/voidgrid/voidgrid-secrets`. It runs one process, the app, which
keeps everything in a single SQLite file (`/data/voidgrid.db`). The image is
x86_64 only for now. Pin a specific version tag for anything you rely on.

The container runs unprivileged, as UID/GID 1000. Nothing in it needs root.

Coming from `v0.1.0-beta.5` or earlier, which used an embedded rqlite
database? Do the one-time export in [Moving from rqlite](#moving-from-rqlite)
before upgrading.

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

If you supply the key file yourself instead, it must be readable by UID
1000 and must not be accessible to group or others (mode `0600`) - the
service refuses to load a key file with looser permissions.

### Keeping the key out of Docker volumes

A named volume keeps the key inside Docker's storage, next to everything
else. If you would rather have it at a host path of your choice, outside
every Docker volume (so a copy or backup of the data volume can never
contain it), mount it as a Compose secret. The app already looks for it at
`/run/secrets/voidgrid-root-key`, which is where Docker mounts secrets.

Generate the key on the host, into a directory UID 1000 can write to:

```
docker run --rm --user 1000:1000 -v "$PWD/keys":/k ghcr.io/voidgrid/voidgrid-secrets:beta keygen -path /k/voidgrid-root-key
```

That creates `keys/voidgrid-root-key` owned by UID 1000 with mode `0600`. If
your host user is not UID 1000, run `chown 1000:1000` on the file afterwards.
Then, in your compose file, drop the `voidgrid-root-key` volume and its
mount at `/run/secrets`, and add:

```yaml
services:
  voidgrid-secrets:
    secrets:
      - voidgrid-root-key

secrets:
  voidgrid-root-key:
    file: ./keys/voidgrid-root-key
```

Plain Compose (without Swarm) bind-mounts the file with its host owner and
mode, and ignores the `uid`, `gid` and `mode` options on the secret, so the
file itself must be right. If it isn't, the container exits with the reason
in its log:

| Host file | Log message |
|---|---|
| mode `0644` (or any group/other access) | `root key file must not be group- or other-accessible (expected mode 0600)` |
| mode `0600` but owned by another user, such as root | `read root key file: open /run/secrets/voidgrid-root-key: permission denied` |

Swarm secrets work the same way in principle but are mounted root-owned and
world-readable by default; you would need to set the secret's `uid` to `1000`
and its `mode` to `0400` on the service. That is untested here.

### What the root key does and does not protect against

The app has to read the key to decrypt your secrets without you being
there, so the key is always readable by something. What it protects against
is a stolen database file, backup or data volume, because those are useless
without the key. It does not protect against root on the host (who can read
the key file, the app's memory, or exec into the container) or against an
attacker running code inside the app.

So: keep the key apart from the database in your backups, keep the host
locked down, and keep a safe copy of the key - losing it makes every secret
unrecoverable. Keeping the key off disk entirely (a passphrase typed at each
start, a hardware module, or a cloud key service) means giving up unattended
restarts or taking on a dependency, and is not supported here.

## 2. Run it

```
docker compose -f examples/docker-compose.yml up -d
```

Or:

```
docker run -d --name voidgrid-secrets --user 1000:1000 -p 8780:8780 -v voidgrid-data:/data -v voidgrid-root-key:/run/secrets ghcr.io/voidgrid/voidgrid-secrets:beta
```

`/data` holds the SQLite database; `/run/secrets` holds the root key. Back
up both volumes.

## 3. HTTPS, or a trusted network

The app serves plain HTTP on port 8780 (not TLS, despite what the port
number might suggest) and has no TLS of its own. Sign-in cookies are
marked `Secure`, which browsers drop over plain HTTP, so by default sign-in
works only over HTTPS: put a reverse proxy (Caddy, Traefik, nginx) in front
of it and have it send `X-Forwarded-Proto: https`.

**HSTS belongs on the proxy.** Once your proxy serves the app over HTTPS, have
it also send `Strict-Transport-Security: max-age=31536000`, so browsers
refuse to fall back to plain HTTP for that hostname. The app doesn't send it
itself because it also serves plain HTTP on the trusted networks below, and
HSTS only applies to the hostname the header came from, not to the LAN
address. Start with a short `max-age` (a day) while you check that nothing
else on the same domain still needs plain HTTP, and avoid `includeSubDomains`
unless every subdomain is HTTPS-only. How you add a header depends on your
proxy; the value is the same everywhere.

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

The database is one SQLite file, `/data/voidgrid.db`, with every secret
encrypted inside it by the key in the root-key volume. **Back up both from
the same moment**: a database is useless without the key it was written
under.

**The database** - a consistent copy while the server keeps running, no
pause needed:

```
docker compose exec -T voidgrid-secrets voidgrid-secrets backup > voidgrid.db
```

`-T` is needed: `docker compose exec` otherwise allocates a terminal, and
the command refuses to write a database to a terminal. Don't copy `/data/voidgrid.db` out of a running container by hand - a live
SQLite file is not safe to copy that way.

**The root key** - copy its volume. Find the real volume names first
(compose prefixes them with the project name):

```
docker volume ls | grep voidgrid
```

Then, substituting the key volume's name:

```
docker run --rm -v KEY_VOLUME:/v:ro -v "$PWD":/backup alpine tar czf /backup/voidgrid-root-key.tgz -C /v .
```

The key archive is as sensitive as the secrets themselves: keep it somewhere
you trust, and consider storing it apart from the database copy.

**Restore** - stop the server, put the database file back, restore the key,
start:

```
docker compose stop voidgrid-secrets; docker run --rm -v DATA_VOLUME:/d -v "$PWD":/backup alpine sh -c 'rm -f /d/voidgrid.db /d/voidgrid.db-wal /d/voidgrid.db-shm; cp /backup/voidgrid.db /d/voidgrid.db; chown 1000:1000 /d /d/voidgrid.db; chmod 600 /d/voidgrid.db'
```

```
docker run --rm -v KEY_VOLUME:/v -v "$PWD":/backup alpine sh -c 'rm -rf /v/* /v/.[!.]* ; tar xzf /backup/voidgrid-root-key.tgz -C /v'; docker compose start voidgrid-secrets
```

The `chown` covers the directory as well as the file: SQLite creates its
`-wal` and `-shm` files next to the database, so UID 1000 must be able to
write there. This replaces what is currently in those volumes, so only run
it when you mean to. Restore the database and the key from the same backup.

## Looking inside the database

The image includes the `sqlite3` command-line tool. Open the database
**read-only** - it is safe while the server runs - to check on it:

```
docker compose exec voidgrid-secrets sqlite3 -readonly /data/voidgrid.db "SELECT (SELECT count(*) FROM secrets) AS secrets, (SELECT count(*) FROM machine_tokens) AS tokens, (SELECT count(*) FROM machine_token_grants) AS grants, (SELECT count(*) FROM audit_log) AS audit"
```

```
docker compose exec voidgrid-secrets sqlite3 -readonly /data/voidgrid.db "PRAGMA integrity_check"
```

The second prints `ok` for a healthy file. Secret names, token
descriptions and the audit log are readable; secret values are stored
encrypted and show as ciphertext. **Don't write with it.** The app keeps
rules the database can't (encryption bound to each row, audit entries,
at-most-one account); change things through the web UI or API, and restore a
backup if you need to go back.

## Moving from rqlite

Up to `v0.1.0-beta.5` the data lived in an embedded rqlite database.
Newer releases use one SQLite file instead. rqlite's own database is a
SQLite file and can hand it over, so the move is an export on your running
old container, then an upgrade:

1. **Copy both volumes first**, in case you want to go back (with the old
   container stopped, for example `tar` each volume as in the old backup
   instructions).
2. **Export**, still on the old image:

   ```
   docker compose exec voidgrid-secrets wget -qO /data/voidgrid.db http://127.0.0.1:4001/db/backup
   ```
3. **Upgrade**:

   ```
   docker compose pull voidgrid-secrets; docker compose up -d voidgrid-secrets
   ```
4. **Check** that you can sign in and that your tokens still work. Then
   optionally reclaim the old store:

   ```
   docker compose exec voidgrid-secrets rm -rf /data/rqlite
   ```

If you upgrade without exporting, the new version refuses to start and
tells you so - it will not create an empty database next to your old data.
Nothing is lost; go back to step 2 with the old image. `VOIDGRID_RQLITE_ADDR`
and `RQLITE_DATA_DIR` no longer exist; drop them from your compose file if
you set them.

## Upgrading

1. Back up (above). Coming from `v0.1.0-beta.5` or earlier? Follow
   [Moving from rqlite](#moving-from-rqlite) instead - it is a one-time step.
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
`/api/v1/setup/status`, which only answers once the app has opened and
migrated its database. `docker ps` shows `healthy`, and other services can wait for
it with `depends_on: voidgrid-secrets: condition: service_healthy`.

## Restarting

The container restarts fully unattended: the root key comes from its
volume and the database persists in its volume. `docker stop` shuts the app
down cleanly, so its write-ahead log is folded into the database file. If OIDC is configured and the
identity provider is unreachable when the container starts, the service
still starts; OIDC sign-in stays unavailable until the next restart with
the provider reachable, and recovery-code login keeps working meanwhile.

## Environment variables

The first three are set in the image (the export directory follows the database path); you normally don't need to change
them. `VOIDGRID_HTTP_ALLOWED_NETS` is yours to set.

| Variable | Default in the image | Purpose |
|---|---|---|
| `VOIDGRID_LISTEN_ADDR` | `0.0.0.0:8780` | Address the API + web UI bind to |
| `VOIDGRID_DB_PATH` | `/data/voidgrid.db` | The SQLite database file |
| `VOIDGRID_ROOT_KEY_PATH` | `/run/secrets/voidgrid-root-key` | Root encryption key file |
| `VOIDGRID_EXPORT_DIR` | `bin` beside the database (`/data/bin`) | Where the server publishes its own executable for consumers to mount; empty turns it off. See [runtime-injection.md](runtime-injection.md#2-get-the-binary-into-the-container) |
| `VOIDGRID_HTTP_ALLOWED_NETS` | empty | Comma-separated CIDRs allowed to sign in over plain HTTP; see [section 3](#3-https-or-a-trusted-network) |

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
