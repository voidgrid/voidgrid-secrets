package model

import "time"

// SecretGroup is a named set of secrets, used only by the web UI to tick
// several secrets at once. Grants know nothing about groups.
type SecretGroup struct {
	ID        int64
	Name      string
	CreatedAt time.Time
	// SecretIDs are the group's members, ascending.
	SecretIDs []int64
}
