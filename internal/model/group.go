package model

import "time"

// Group is a collection of users that can own and be granted access to
// secrets together.
type Group struct {
	ID          int64
	Name        string
	Description string
	CreatedAt   time.Time
}

// GroupRole is a user's role within a group: a member has read access to
// secrets owned by the group, an admin additionally has write access and
// can manage membership.
type GroupRole string

const (
	GroupRoleMember GroupRole = "member"
	GroupRoleAdmin  GroupRole = "admin"
)

// GroupMember is a user's membership in a group.
type GroupMember struct {
	UserID   int64
	GroupID  int64
	Username string
	Role     GroupRole
}

// SecretShare grants a user or group explicit access to a secret, beyond
// whatever access its ownership already implies.
type SecretShare struct {
	SecretID    int64
	GranteeType OwnerType // OwnerUser or OwnerGroup
	GranteeID   int64
	Permission  string // "read" or "write"
	GrantedBy   int64
	GrantedAt   time.Time
}
