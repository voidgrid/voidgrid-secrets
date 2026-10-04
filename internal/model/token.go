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
}
