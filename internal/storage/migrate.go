package storage

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/voidgrid/voidgrid-secrets/migrations"
)

// Migrate applies any migration files embedded in the migrations package
// that have not yet been recorded in the schema_migrations table, in
// filename order. Each file is applied, and recorded, in one transaction.
func (db *DB) Migrate(ctx context.Context) error {
	if _, err := db.sql.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TEXT NOT NULL
		)`,
	); err != nil {
		return fmt.Errorf("storage: ensure schema_migrations table: %w", err)
	}

	applied, err := db.appliedMigrations(ctx)
	if err != nil {
		return err
	}

	names, err := migrationFileNames()
	if err != nil {
		return err
	}

	for _, name := range names {
		if applied[name] {
			continue
		}

		raw, err := migrations.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("storage: read migration %s: %w", name, err)
		}

		var stmts []Statement
		for _, q := range splitStatements(string(raw)) {
			stmts = append(stmts, Statement{Query: q})
		}
		if len(stmts) == 0 {
			continue
		}
		stmts = append(stmts, Statement{
			Query:     "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
			Arguments: []interface{}{name, nowTimestamp()},
		})
		results, err := db.write(ctx, stmts)
		if err := writeErrAll("apply migration "+name, results, err); err != nil {
			return err
		}
	}

	return nil
}

func migrationFileNames() ([]string, error) {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("storage: read migrations dir: %w", err)
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func (db *DB) appliedMigrations(ctx context.Context) (map[string]bool, error) {
	qr, err := db.queryString(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("storage: list applied migrations: %w", err)
	}
	applied := make(map[string]bool)
	for qr.Next() {
		var version string
		if err := qr.Scan(&version); err != nil {
			return nil, fmt.Errorf("storage: scan applied migration: %w", err)
		}
		applied[version] = true
	}
	return applied, nil
}

// splitStatements splits a migration file's contents into individual SQL
// statements on "statement;" boundaries. This is intentionally simple:
// migration files are authored by project maintainers, not generated from
// untrusted input, so a naive split is sufficient as long as no statement
// embeds a literal semicolon inside a string value.
func splitStatements(sql string) []string {
	parts := strings.Split(sql, ";")
	statements := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			statements = append(statements, p)
		}
	}
	return statements
}
