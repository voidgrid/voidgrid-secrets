// Package migrations embeds the SQL migration files applied to the rqlite
// database on startup. Keeping the .sql files at the repo root (rather than
// inside internal/storage) lets an operator find and read them directly,
// while this small package exposes them to Go code via embed.FS.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
