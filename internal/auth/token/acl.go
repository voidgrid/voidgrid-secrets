package token

import "github.com/voidgrid/voidgrid-secrets/internal/model"

// CanAccess reports whether grants give permission on secretID. A "write"
// grant implies "read" access to the same secret.
func CanAccess(grants []model.TokenGrant, secretID int64, permission string) bool {
	for _, g := range grants {
		if g.SecretID != secretID {
			continue
		}
		if g.Permission == permission || (g.Permission == "write" && permission == "read") {
			return true
		}
	}
	return false
}
