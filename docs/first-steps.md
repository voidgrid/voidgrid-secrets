# First steps

You've finished the setup wizard and are signed in. This walks one secret
all the way to a container using it.

## 1. Add a secret

Go to **secrets** and choose **new secret**. Give it a name (`db-password`)
and a value. The list shows names only; open a secret and press **show** to
reveal its value (each reveal is recorded in the [audit log](audit-log.md)).
On a secret's page you can also change its value, rename it, or delete it.
Deleting a secret also removes every token grant on it.

## 2. Create a token for the service

Go to **tokens**, enter a description (`myapp`) and **create**. The token
is shown **once** - copy it now and save it to a file the service can read
(for example `./myapp-voidgrid-token`). Never commit that file. Give each
service its own token.

## 3. Grant it the secret

Open the token (click its id or description in the list; right after
creating it there is a link). Its page is one editor for everything the
token may use: tick each secret it needs, leave permission on **read**, and
optionally set the environment variable name (`MYAPP_DB_PASSWORD`). A blank
name is derived from the secret's name (`db-password` becomes
`DB_PASSWORD`) and shown in grey. Press **save**: the ticked secrets become
the token's complete set, so unticking one removes it. A save is all or
nothing - if a name is invalid or clashes with another, nothing changes and
you keep what you typed.

You can also start from the secret: on a secret's page, **add to a token**
lists the tokens that can still take it (not revoked or expired, and without
a grant on it yet).

`run` reads its secrets when the container starts, so restart the container
to drop one; the agent removes the file on its next poll. Revoking the
token cuts off everything at once.

### Groups

If several tokens need the same handful of secrets, make a **group** (the
**groups** page) and tick its secrets. On a token's page, each group appears
as a quick-select checkbox: ticking it ticks all the group's secrets, and you
can still untick any of them before saving. A secret can be in several
groups. Groups only help you tick things in the web UI. Grants, tokens and
the API never refer to them, so changing or deleting a group changes no
access.

## 4. Use it from a container

Check the token works from the host:

```
curl -s -H "Authorization: Bearer $(cat ./myapp-voidgrid-token)" http://localhost:8780/api/v1/env
```

Then give the container its secrets at startup with
`voidgrid-secrets run`, which puts them into the container's environment
without writing them to disk or to `docker inspect`. Setting this up takes
three small compose edits - copy the binary in, point the entrypoint at it,
mount the token - all shown step by step in
[runtime-injection.md](runtime-injection.md), along with file mode for
images that read `*_FILE` variables and a sidecar agent mode.

If you edit a secret's value later, restart the consuming container to
pick it up (agent mode picks changes up on its own).
