// Package session implements human session authentication: generating
// opaque session tokens for the web UI, the HTTP middleware (and cookie
// helpers) that validate them, and the password+TOTP login flow.
package session

import "github.com/voidgrid/voidgrid-secrets/internal/crypto"

// Prefix is prepended to every generated session token, distinct from
// machine tokens' "vgs_" prefix so the two can never be confused in logs
// or if a value ends up in the wrong header by mistake.
const Prefix = "vgs_sess_"

// Generate returns a new random session token in the form
// "vgs_sess_<base64url>".
func Generate() (string, error) {
	return crypto.GenerateOpaqueToken(Prefix)
}
