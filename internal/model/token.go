package model

import "time"

// MachineToken is a scoped bearer credential issued to an automated
// consumer (e.g. a docker-compose service) for programmatic secret access,
// distinct from the account's web session.
type MachineToken struct {
	ID          int64
	Description string
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	RevokedAt   *time.Time
	LastUsedAt  *time.Time
}

// TokenGrant gives a machine token a permission on one secret.
type TokenGrant struct {
	TokenID    int64
	SecretID   int64
	SecretName string
	Permission string // "read" or "write"
	// EnvName is the explicit environment variable name the secret is
	// exposed under by `voidgrid-secrets run` and the agent, or "" to
	// derive it from the secret's name (see internal/envname).
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
