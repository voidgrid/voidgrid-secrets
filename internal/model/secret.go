// Package model holds domain types shared across the storage, API, and web
// layers.
package model

import "time"

// Secret is a secret's metadata. Its decrypted value is never part of this
// type - callers must explicitly request a reveal, which is audited.
type Secret struct {
	ID         int64
	Name       string
	KeyVersion int
	CreatedAt  time.Time
	UpdatedAt  time.Time
}
