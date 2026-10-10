package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// CheckLegacy refuses to start against a data directory that holds the
// old rqlite store but no SQLite database: starting anyway would show the
// first-run setup wizard over an empty database while the real data sits
// unread next to it.
func CheckLegacy(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	legacy := filepath.Join(filepath.Dir(path), "rqlite")
	if st, err := os.Stat(legacy); err == nil && st.IsDir() {
		return fmt.Errorf("found an old rqlite data directory (%s) but no database at %s: this version keeps everything in one SQLite file - export the old data first, see docs/deployment.md, \"Moving from rqlite\"", legacy, path)
	}
	return nil
}

// CheckIntegrity returns problems SQLite reports with the database file or
// with foreign-key relationships; none means it looks healthy.
func (db *DB) CheckIntegrity(ctx context.Context) ([]string, error) {
	var problems []string
	qr, err := db.queryString(ctx, "PRAGMA quick_check")
	if err != nil {
		return nil, fmt.Errorf("storage: integrity check: %w", err)
	}
	for qr.Next() {
		var line string
		if err := qr.Scan(&line); err != nil {
			return nil, fmt.Errorf("storage: integrity check: %w", err)
		}
		if line != "ok" {
			problems = append(problems, "integrity: "+line)
		}
	}
	fk, err := db.queryString(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return nil, fmt.Errorf("storage: foreign key check: %w", err)
	}
	for fk.Next() {
		var table, rowid, parent, idx any
		if err := fk.Scan(&table, &rowid, &parent, &idx); err != nil {
			return nil, fmt.Errorf("storage: foreign key check: %w", err)
		}
		problems = append(problems, fmt.Sprintf("foreign key: row %v of %v has no parent in %v", rowid, table, parent))
	}
	return problems, nil
}

// BackupTo writes a consistent, standalone copy of the database to path
// (which must not exist) with mode 0600, while the server keeps running.
func (db *DB) BackupTo(ctx context.Context, path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("storage: backup target %s already exists", path)
	}
	if _, err := db.sql.ExecContext(ctx, "VACUUM INTO ?", path); err != nil {
		return fmt.Errorf("storage: backup: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("storage: restrict backup file mode: %w", err)
	}
	return nil
}
