// Package envname holds the rules for the environment variable names that
// machine-token grants expose secrets under (see `voidgrid-secrets run`).
package envname

import (
	"regexp"
	"strings"
)

var validName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// Valid reports whether name is an acceptable environment variable name:
// uppercase letters, digits and underscores, not starting with a digit.
func Valid(name string) bool {
	return validName.MatchString(name)
}

// Derive turns a secret's name into the default environment variable name
// for it: uppercased, with every character other than A-Z and 0-9 replaced
// by an underscore, and an underscore prefixed if it would start with a
// digit. "db-password" becomes "DB_PASSWORD".
func Derive(secretName string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(secretName) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" || (out[0] >= '0' && out[0] <= '9') {
		out = "_" + out
	}
	return out
}
