package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// HashToken returns the hex-encoded SHA-256 digest of token, suitable for
// storing in place of the plaintext token.
//
// Unlike passwords, machine tokens are generated with high entropy (see
// internal/auth/token), so a fast cryptographic hash is sufficient here —
// Argon2id's deliberate slowness exists to resist brute-forcing low-entropy
// human input, which doesn't apply to a random 256-bit token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// VerifyTokenHash reports whether token hashes to hash, using a
// constant-time comparison to avoid leaking timing information about the
// stored hash.
func VerifyTokenHash(token, hash string) bool {
	got := HashToken(token)
	return subtle.ConstantTimeCompare([]byte(got), []byte(hash)) == 1
}
