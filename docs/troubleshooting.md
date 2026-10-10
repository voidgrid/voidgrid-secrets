# Troubleshooting

Find the symptom, then the fix. Commands assume you run them from the
directory with your compose file; with plain `docker run`, use
`docker logs <container>` and `docker exec <container> ...` instead of the
`docker compose` forms.

## The web UI

### "Sign-in over plain HTTP is not allowed from this address"

You reached the app over `http://` from an address that is not listed in
`VOIDGRID_HTTP_ALLOWED_NETS`. Either put a reverse proxy with HTTPS in front
(it must send `X-Forwarded-Proto: https`), or list your networks in the
`.env` file next to your compose file and recreate the container:

```
VOIDGRID_HTTP_ALLOWED_NETS=192.168.1.0/24,100.64.0.0/10,fd7a:115c:a1e0::/48
```

Details and the Tailscale ranges are in
[deployment.md](deployment.md#3-https-or-a-trusted-network). Two traps:

- **Signing in from the Docker host itself:** the server sees the compose
  network's gateway as the client, not `127.0.0.1` - for example
  `172.19.0.1`. Add `172.16.0.0/12`, which covers Docker's default ranges.
- **Behind a reverse proxy:** the server sees the proxy's address. Make the
  proxy speak HTTPS to browsers and send `X-Forwarded-Proto: https`.

To see which address the server sees, make one failed sign-in and look at
the `ip` in its `login_failed` entry in the audit log (`/audit`).

### "too many failed attempts - try again in 15 minutes"

Ten failed sign-ins within 15 minutes lock password sign-in. Wait it out, or
use a recovery code at `/recover` - see
[authentication.md](authentication.md#recovery).

### I lost the setup token

It exists only in the running process and a restart prints a new one, as long
as setup isn't finished:

```
docker compose restart voidgrid-secrets; docker compose logs voidgrid-secrets | grep 'setup token'
```

### "OIDC sign-in is unavailable right now"

The identity provider could not be reached when the container started.
Restart the container once the provider is reachable. Until then, use a
recovery code at `/recover`. Provider-side "redirect URI mismatch" errors
mean the callback registered with the provider differs from the one shown on
the setup page; they must match exactly.

### The audit log shows my proxy's address, not mine

Behind a reverse proxy each entry records two addresses: `ip` is the
connecting address (your proxy) and `forwarded_for` is what the proxy
reported as the client. The app records `forwarded_for` as received and never
trusts it for decisions. If `forwarded_for` is your router's address rather
than your device's, the proxy is receiving your traffic through the router
(NAT hairpin) and the real address is already gone before the app sees it -
fix that at the proxy or network, not in the app. Both fields are in the
details column of each entry in `/audit`.

### I lost my password, authenticator or recovery codes

See [authentication.md](authentication.md#recovery); the break-glass command
needs only access to the container.

## The server container

### It exits or keeps restarting

If the app can't start it exits with code 1, and a restart policy such as
`restart: unless-stopped` then restarts it in a loop (`docker ps` shows
`Restarting`). The last line of the log is the cause:

```
docker compose logs voidgrid-secrets
```

- **`load root key (run 'voidgrid-secrets keygen' first ...): crypto: stat root
  key file ...: no such file or directory`** - there is no root key at the
  expected path. Generate it - see
  [deployment.md](deployment.md#1-generate-the-root-key) - or check that the
  volume or secret is mounted at `/run/secrets`.
- **`crypto: root key file must not be group- or other-accessible (expected mode
  0600)`** - fix the file's mode (`chmod 600`), and make sure UID 1000 can read
  it.
- **`open database ...: attempt to write a readonly database ... must be
  writable by this user`** - UID 1000 can't write to `/data`. SQLite creates
  its `-wal` and `-shm` files beside the database, so the directory as well as
  the file must belong to UID 1000. This happens when a volume was filled
  through another container (a restore, for example); fix it with `chown
  1000:1000` on the directory and `voidgrid.db`, as in the restore command in
  [deployment.md](deployment.md#backup-and-restore).
- **`found an old rqlite data directory ... but no database`** - you
  upgraded from `v0.1.0-beta.5` or earlier without exporting your data. Nothing
  is lost; follow [Moving from rqlite](deployment.md#moving-from-rqlite).
- **`DATABASE PROBLEM: ...`** near the top of the log - SQLite reported a
  problem with the file or its relationships. Look with `docker compose exec
  voidgrid-secrets sqlite3 -readonly /data/voidgrid.db "PRAGMA integrity_check"`
  ([deployment.md](deployment.md#looking-inside-the-database)); if it isn't
  `ok`, restore from a backup.
- **The key was lost or replaced:** every stored secret is unrecoverable
  without the key it was encrypted under. Restore the key volume from a
  backup taken together with the database
  ([deployment.md](deployment.md#backup-and-restore)).

### `unhealthy` in `docker ps`

The healthcheck asks the app for `/api/v1/setup/status` every 30 seconds, so
`unhealthy` means the app is running but not answering. Check the log; if it
shows nothing, restart the container and report it.

### After upgrading from v0.1.0-beta.1 nothing answers on 8443

The default port is now 8780. Update the published port in your compose file,
your reverse proxy, and `VOIDGRID_URL` in consumers.

## Consumers (`run` and the agent)

### The app starts but its secrets are missing

1. Read the consumer's start-up output. `run` prints one line naming the
   variables it injected:

   ```
   voidgrid-secrets run: injecting 2 variable(s): TMDB_API_KEY, SEERR_API_KEY
   ```

   If the names you expect aren't there, the token isn't granted those
   secrets. Open the token in the web UI (**tokens**, then the token), tick
   them, and **save**. A token with no grants at all makes `run` fail with
   "this token has no readable secrets" instead of starting.
2. Remember that `docker exec` shows a fresh environment: the secrets are in
   the app's own process only. To check names without printing values:

   ```
   docker compose exec myapp sh -c "tr '\0' '\n' < /proc/1/environ | cut -d= -f1"
   ```
3. `run` reads its secrets once, at start. After changing a grant or a value,
   restart the consumer. The agent picks changes up by itself.
4. In `/audit`, a consumer start-up shows one `reveal` entry (`via=env`) per
   secret for that token. No entries and no `token_auth_failed` means the
   token was valid but granted nothing.

### `run: fetching secrets: server returned 401` (or 403)

The token is wrong, revoked or expired. Check the token file: it must hold
the token exactly as shown at creation, and be readable by the user the
consumer runs as. A rejected token appears as `token_auth_failed` in the
audit log. A revoked token can't be revived; create a new one.

### `run: no machine token` / `token file ... is empty`

`run` found no token. Mount one at `/run/secrets/voidgrid-token`, or set
`--token-file`, `VOIDGRID_TOKEN_FILE` or `VOIDGRID_TOKEN`
([runtime-injection.md](runtime-injection.md)).

### `run: waiting for http://...` and then it gives up

The server is unreachable from the consumer: check `VOIDGRID_URL`, that both
containers share a Docker network, and that the server is healthy. `run`
retries for `--timeout` (30 seconds by default), and a "setup wizard must be
completed first" answer (503) means first-run setup isn't finished yet.

### Agent: the consumer's directory is empty

Read the agent's log:

```
docker compose logs voidgrid-secrets-agent
```

- **"its token has no readable secrets":** grant the token secrets, as above.
- **"...; its files have been removed":** the token was rejected (revoked or
  wrong), so the agent removed that consumer's files on purpose.
- **"...; keeping its last values":** the server is unreachable; the files
  stay as they were until it returns.
- **"the agent is not in group ...":** add that group to the agent's
  `group_add`, as in the example in
  [runtime-injection.md](runtime-injection.md#agent-mode-no-wrapper).
- **The consumer can't read the files:** the consumer must run in the group
  given as `gid=` for its target (`group_add`).

### Two secrets would use the same environment variable name

Either give one of them a different name in the token editor, or rename a
secret. A token can't expose two secrets under one name; the editor refuses
the whole save and tells you which name clashed.
