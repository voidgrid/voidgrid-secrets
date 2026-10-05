package model

import "time"

// MachineToken is a scoped bearer credential issued to an automated
// consumer (e.g. a docker-compose service) for programmatic secret access,
// distinct from a human's web session.
type MachineToken struct {
	ID          int64
	Description string
	CreatedBy   int64
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	RevokedAt   *time.Time
	LastUsedAt  *time.Time
}

// TokenACL grants a machine token a permission on a single resource
// (a specific secret or an entire group).
type TokenACL struct {
	TokenID      int64
	ResourceType string // "secret" or "group"
	ResourceID   int64
	Permission   string // "read" or "write"
	// EnvName is the explicit environment variable name a secret grant is
	// exposed under by `voidgrid-secrets run`, or "" to derive it from the
	// secret's name (see internal/envname). Unused for group grants.
	EnvName string
}

// EnvGrant is one secret a machine token can read, with the effective
// environment variable name it's exposed under.
type EnvGrant struct {
	SecretID   int64
	SecretName string
	EnvName    string
	Permission string
	// SecretUpdatedAt is when the secret's value last changed, so a client
	// polling GET /env can tell whether anything it holds is stale.
	SecretUpdatedAt time.Time
}
