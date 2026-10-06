# Authentication

voidgrid-secrets has **one account**: yours. The setup wizard creates it,
and it can do everything - manage secrets and machine tokens, and read the
audit log. Automated consumers never sign in; they use machine tokens
(see [deployment.md](deployment.md)).

The account signs in with one method, chosen once during setup:
**password + TOTP**, or **OIDC**.

## Setup

Until setup is complete, every page redirects to `/setup`. Every setup
step needs the **setup token** the server prints to its log at startup
(see [deployment.md](deployment.md#4-finish-first-run-setup)), so only
someone who can read that log can run it. Wrong tokens are refused (403)
and recorded in the [audit log](audit-log.md).

### Password + TOTP

At `/setup`:

1. Enter the setup token, a username, and a password of at least 14
   characters.
2. Scan the QR code with an authenticator app (or enter the secret shown
   beneath it), then confirm with a current code. TOTP is always
   required; there is no way to skip it.
3. Save the **recovery codes** shown next - see below.

Lost the QR code before confirming? Start again at `/setup`; the
unfinished account is replaced.

### OIDC

At `/setup`, choose "configure OIDC" (or go to `/setup/oidc`), then enter:

- **Setup token** - from the server log. It's checked before anything
  else, including contacting the issuer.
- **Issuer URL** - exactly as the provider advertises it.
- **Client ID** and **client secret** - from the client you register with
  the provider.
- **Redirect URI** - prefilled from the address you're using. It must be
  the externally reachable HTTPS address followed by
  `/login/oidc/callback`, e.g. `https://secrets.example.com/login/oidc/callback`,
  and must match what you register with the provider exactly.

Setup checks the issuer with OIDC discovery before saving anything, so a
wrong or unreachable issuer fails right there. Then **sign in through the
provider once** (the link on the next page, valid for 15 minutes): that
identity becomes the account, setup finishes, and you're shown your
recovery codes.

Register the client with the same callback URL. It requests the `openid`,
`profile` and `email` scopes and uses the authorization code flow with
PKCE. After setup, **only the identity that finished setup can sign in**;
anyone else your provider lets through is refused (and recorded in the
audit log as a failed sign-in).

## Recovery

If you lose your password or authenticator - or your OIDC provider is
unreachable - go to **`/recover`** (linked from the sign-in page) and
enter one of your **recovery codes**:

- For a password account you then choose a new password and enroll a new
  authenticator. For an OIDC account nothing else is needed.
- Either way you get a **fresh set of recovery codes** (the old ones stop
  working) and **every session is signed out**.
- A recovery code doesn't sign you in by itself; it only starts this
  reset, which must be finished within 15 minutes.

Recovery codes:

- 10 per set, **shown exactly once** - save them somewhere safe.
- Each works once. Only hashes are stored; nobody can retrieve them.
- They're accepted in any case, with or without the hyphens.

### Break-glass: when the recovery codes are gone too

Run this inside the server's container:

```
docker exec voidgrid-secrets voidgrid-secrets recover
```

It prints a one-time code (valid 15 minutes) that works at `/recover`
exactly like a recovery code. Only someone who can run commands in the
container can do this - the same person who can read the setup token, the
root key and the database anyway. It's recorded in the audit log.

## Sessions

Web sessions last 24 hours and use a `Secure`, `HttpOnly`,
`SameSite=Strict` cookie, which is why the UI needs HTTPS. Signing out
ends the session on the server; a recovery ends all of them.

Form submissions and API calls made with a session cookie are refused
(403) when the browser marks them as coming from another origin -
including another subdomain of the same domain, which `SameSite=Strict`
alone would let through. Scripts and machine tokens, which send no such
headers, are unaffected.

## Failed attempts

After 10 failed sign-ins within 15 minutes, password sign-in is refused
(429) until the 15 minutes are up, even with the right credentials; the
same applies, separately, to 10 wrong codes at `/recover`. Sessions
already open and OIDC sign-in aren't affected. Anyone who can reach the
instance can trigger a lockout on purpose, so password sign-in (or
recovery) can be kept unavailable that way while it lasts.
