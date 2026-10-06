# Audit log

Every action that reveals a secret value or changes something is
recorded, along with failed and refused attempts. Reads that don't reveal
a value (lists, metadata pages) aren't.

Admins can read the log in the web UI at **`/admin/audit`** (the "audit"
link in the top bar), or through the API at `GET /api/v1/admin/audit`.
Nobody else can.

## What's recorded

| Area | Actions |
|---|---|
| Sign-in | `login`, `login_failed`, `login_locked_out`, `recovery_login`, `recovery_login_failed`, `logout`, `token_auth_failed` |
| Setup | `setup_token_rejected`, `setup_admin_created`, `setup_completed` |
| Secrets | `secret_create`, `secret_update`, `reveal`, `access_denied`, `share_create`, `share_delete` |
| Machine tokens | `token_create`, `token_revoke`, `token_grant` |
| Users and groups | `user_create`, `user_disable`, `user_enable`, `group_create`, `group_member_add`, `group_member_remove` |
| Server | `encryption_upgraded` |

`reveal` covers every way a value leaves the server: the web UI, the
single-secret API endpoint, and `GET /api/v1/env` (`voidgrid-secrets run`
and the agent - one entry per secret). An agent's check that finds
nothing changed reveals nothing and isn't recorded.

Each entry has:

- **When**, in UTC.
- **Actor**: a user, a machine token, `anonymous` (failed sign-ins,
  setup attempts, rejected tokens), or `system` (the server itself).
- **Action** and **resource** (a secret, user, group, token or setup),
  shown by name where it still exists.
- **Details**, such as why a sign-in failed (`wrong password`,
  `wrong TOTP code`, `unknown user`, ...), the permission a grant or share
  gave, or the environment variable name a token read a secret under.
- **Where from**: the connecting address (`ip`), plus the
  `X-Forwarded-For` header and user agent as received. Behind a reverse
  proxy, `ip` is the proxy; `forwarded_for` is whatever the proxy (or, if
  it doesn't set one, the client) sent, so treat it as a hint.

Secret values, passwords, tokens, TOTP codes and recovery codes are never
recorded. Failure reasons are visible only here, never to the person
signing in.

## Viewing and filtering

The viewer shows the newest 100 entries, with a link to older ones. Filter
by action, actor (type and id) and resource (type and id); clicking an
action or a resource in the table filters by it. The API takes the same
filters as query parameters - `action`, `actor_type`, `actor_id`,
`resource_type`, `resource_id` - and pages with `before` (the
`next_before` of the previous page).

## Limits

- Entries are kept indefinitely; there's no pruning yet.
- A value is never revealed unrecorded: if writing the `reveal` entry
  fails, the request fails. For other actions, the change has already
  happened by the time it's recorded, so a failure to record is logged to
  the server's stderr instead.
- The log lives in the same database as everything else, so anyone who
  can write to the database directly could alter it.
