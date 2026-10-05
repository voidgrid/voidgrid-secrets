# Authentication

The web UI supports one sign-in method per deployment, chosen once in the
first-run setup wizard: **password + TOTP**, or **OIDC**. Automated
consumers never use either - they use machine tokens (see
[deployment.md](deployment.md)).

Until setup is complete, every page redirects to `/setup`, and anyone who
can reach the instance can complete it. Finish setup before exposing the
instance.

## Password + TOTP

At `/setup`:

1. Create the admin account. Passwords must be at least 14 characters.
2. Scan the QR code with an authenticator app (or enter the secret shown
   beneath it), then confirm with a current code. TOTP is always
   required for password accounts; there is no way to skip it.
3. Save the **recovery codes** shown next - see below.

Admins can create further password accounts at `/admin/users`; each gets
its own TOTP enrollment, shown once.

## OIDC

At `/setup`, choose "configure OIDC" (or go to `/setup/oidc`), then enter:

- **Issuer URL** - exactly as the provider advertises it.
- **Client ID** and **client secret** - from the client you register with
  the provider.
- **Redirect URI** - prefilled from the address you're using. It must be
  the externally reachable HTTPS address followed by
  `/login/oidc/callback`, e.g. `https://secrets.example.com/login/oidc/callback`,
  and must match what you register with the provider exactly.

Setup checks the issuer by performing OIDC discovery before saving
anything, so a wrong or unreachable issuer fails right there.

Register the client with your provider with that same callback URL. The
client requests the `openid`, `profile`, and `email` scopes and uses the
authorization code flow with PKCE. With Pocket ID, restrict the client to
the group(s) of people who should have access: **anyone the provider
lets sign in to this client gets an account**, created automatically on
their first login.

- The **first person to sign in becomes the admin.**
- Each new OIDC user is shown a batch of **recovery codes** on their first
  sign-in.
- A local username comes from the provider's `preferred_username` claim,
  falling back to the provider's subject ID if that's missing or already
  taken by another account.
- Disabling a user (admin > users) blocks their OIDC sign-in too.

## Recovery codes

Recovery codes are the fallback for both methods: a lost authenticator
device, or an OIDC provider that's down. At `/login/recovery`, sign in
with your username and one code.

- You get 10 codes, **shown exactly once** - save them somewhere safe.
- Each code works one time only.
- Only a hash is stored; nobody can retrieve them later.

Who receives codes:

- The admin created by the password + TOTP setup wizard.
- Every OIDC user, on their first sign-in.

Not yet supported: password accounts created later by an admin don't
receive recovery codes, and there's no way to generate a new batch once
codes are used up or lost.

## Sessions

Web sessions last 24 hours and use a `Secure`, `HttpOnly`,
`SameSite=Strict` cookie, which is why the UI needs HTTPS. Logging out
ends the session on the server.
