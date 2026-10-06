// Package recoverycode generates single-use account-recovery codes: a
// fallback login path for password+TOTP users who lose their device, and
// for OIDC users when the identity provider is unreachable. Codes are
// generated in a set, shown to the user exactly once, and stored only as
// a hash (via internal/crypto.HashToken, the same high-entropy-token
// hashing already used for machine and session tokens).
package recoverycode

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

// Count is how many codes are generated per set, matching the common
// GitHub/Google style of providing a batch of one-time codes rather than
// a single reusable one.
const Count = 10

// codeBytes is the entropy per code: 13 bytes (104 bits), comfortably
// brute-force resistant for a single-use secret - well beyond a TOTP
// code's ~20 bits, since there's no rate-limited, time-boxed window
// protecting it the way TOTP's validity period does.
const codeBytes = 13

// groupSize is how many characters sit between hyphens in a formatted
// code, purely for readability when copying it down by hand.
const groupSize = 5

// Generate returns Count new single-use recovery codes, each formatted as
// hyphen-separated groups of base32 characters (e.g.
// "ABCDE-FGHIJ-KLMNO-PQRST"). Call internal/crypto.HashToken on each
// before storing it - these plaintext values are shown to the user
// exactly once and never persisted as-is.
func Generate() ([]string, error) {
	codes := make([]string, Count)
	for i := range codes {
		raw := make([]byte, codeBytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("recoverycode: generate: %w", err)
		}
		encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
		codes[i] = formatGroups(encoded, groupSize)
	}
	return codes, nil
}

func formatGroups(s string, n int) string {
	var groups []string
	for len(s) > n {
		groups = append(groups, s[:n])
		s = s[n:]
	}
	groups = append(groups, s)
	return strings.Join(groups, "-")
}

// Normalize puts a typed recovery code into the exact form Generate
// produced - uppercase, hyphen-grouped - so it still matches if typed in
// lowercase, without hyphens, or with stray spaces.
func Normalize(code string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		if r != '-' && r != ' ' && r != '\t' {
			b.WriteRune(r)
		}
	}
	return formatGroups(b.String(), groupSize)
}
