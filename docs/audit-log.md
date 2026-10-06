# Audit log

Everything that reveals a secret value or changes something is recorded,
including your own reveals, along with failed and refused attempts.
Pages and API calls that show no value (lists, metadata) aren't.

Read it in the web UI at **`/audit`** (the "audit" link in the top bar),
or through the API at `GET /api/v1/audit`. Machine tokens can't read it.

Entries older than **14 days** are deleted - at startup and once a day.

## What's recorded

| Area | Actions |
|---|---|
| Sign-in | `login`, `login_failed`, `login_locked_out`, `logout`, `token_auth_failed` |
| Setup | `setup_token_rejected`, `setup_account_created`, `setup_completed` |
| Recovery | `recovery_started`, `recovery_failed`, `recovery_completed`, `break_glass_issued` |
| Secrets | `secret_create`, `secret_update`, `secret_rename`, `secret_delete`, `reveal`, `access_denied` |
| Machine tokens | `token_create`, `token_revoke`, `token_grant` |
| Housekeeping | `audit_pruned` |

`reveal` covers every way a value leaves the server: the "show" button in
the web UI (`via=web` - opening a secret's page alone isn't a reveal), the
single-secret API endpoint (`via=api`), and `GET /api/v1/env`
(`voidgrid-secrets run` and the agent, `via=env`, one entry per secret).
An agent check that finds nothing changed reveals nothing and isn't
recorded. `access_denied` is a machine token asking for a secret it isn't
granted.

Each entry has:

- **When**, in UTC.
- **Actor**: you (`user`), a machine token, `anonymous` (failed sign-ins,
  setup and recovery attempts, rejected tokens), or `system` (the server
  itself, or the break-glass `recover` command).
- **Action** and **resource**, with the secret's or token's name where it
  still exists.
- **Details**, such as why a sign-in failed (`wrong password`,
  `wrong TOTP code`, `unknown user`, `not the account owner`, ...), the
  permission a grant gave, a rename's old and new names, or the
  environment variable name a token read a secret under.
- **Where from**: the connecting address (`ip`), plus the
  `X-Forwarded-For` header and user agent as received. Behind a reverse
  proxy, `ip` is the proxy; `forwarded_for` is whatever the proxy (or, if
  it doesn't set one, the client) sent, so treat it as a hint.

Secret values, passwords, tokens, TOTP codes and recovery codes are never
recorded. Failure reasons appear only here, never to whoever is signing
in.

## Viewing and filtering

The viewer shows the newest 100 entries, with a link to older ones. Filter
by action, or by machine token (entries where that token acted or was
acted on); clicking an action or a token in the table filters by it. A
token's page links to its audit trail. The API takes the same filters as
query parameters - `action`, `token_id` - and pages with `before` (the
`next_before` of the previous page).

## Limits

- A value is never revealed unrecorded: if writing the `reveal` entry
  fails, the request fails. For other actions, the change has already
  happened by the time it's recorded, so a failure to record is logged to
  the server's stderr instead.
- The log lives in the same database as everything else, so anyone who
  can write to the database directly could alter it.
