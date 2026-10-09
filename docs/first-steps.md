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

Open the token and, under **grant a secret**, pick the secret, leave
permission on **read**, and optionally set the environment variable name
(`MYAPP_DB_PASSWORD`). If you leave the name blank it is derived from the
secret's name (`db-password` becomes `DB_PASSWORD`). The token's page lists
every secret it can read and the name each will have.

To take a secret away from a token, press **remove** next to it on the
token's page (or revoke the token to cut off everything). `run` reads its
secrets when the container starts, so restart the container to drop one;
the agent removes the file on its next poll.

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
