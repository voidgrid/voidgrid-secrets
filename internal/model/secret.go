// Package model holds domain types shared across the storage, API, and web
// layers.
package model

import "time"

// OwnerType identifies whether a secret or share is owned by a single user
// or a group.
type OwnerType string

const (
	OwnerUser  OwnerType = "user"
	OwnerGroup OwnerType = "group"
)

// Secret is a secret's metadata. Its decrypted value is never part of this
// type — callers must explicitly request a reveal, which is logged and
// audited separately.
type Secret struct {
	ID         int64
	Name       string
	OwnerType  OwnerType
	OwnerID    int64
	KeyVersion int
	CreatedBy  int64
	CreatedAt  time.Time
	UpdatedAt  time.Time
}
