// Package token implements machine-token authentication: generating
// high-entropy bearer tokens for automated secret consumers, and the HTTP
// middleware that validates them on incoming requests.
package token

import "github.com/voidgrid/voidgrid-secrets/internal/crypto"

// Prefix is prepended to every generated token so that tokens are
// recognizable at a glance (in logs, in accidental commits, by secret
// scanners) as voidgrid-secrets machine tokens.
const Prefix = "vgs_"

// Generate returns a new random bearer token in the form "vgs_<base64url>".
func Generate() (string, error) {
	return crypto.GenerateOpaqueToken(Prefix)
}
