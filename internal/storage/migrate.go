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
// statements on ";" boundaries, skipping any ";" inside a "--" or "/* */"
// comment, a 'string' or a "quoted identifier". Comments are dropped, and
// so is any fragment with no SQL in it, so a comment can say anything.
// CREATE TRIGGER bodies (BEGIN ... END with inner semicolons) are not
// supported; no migration uses one.
func splitStatements(sql string) []string {
	var (
		statements []string
		cur        strings.Builder
	)
	flush := func() {
		if stmt := strings.TrimSpace(cur.String()); stmt != "" {
			statements = append(statements, stmt)
		}
		cur.Reset()
	}
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		switch {
		case c == '-' && i+1 < len(sql) && sql[i+1] == '-':
			for i < len(sql) && sql[i] != '\n' {
				i++
			}
			cur.WriteByte('\n')
		case c == '/' && i+1 < len(sql) && sql[i+1] == '*':
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				i = len(sql)
			} else {
				i += 2 + end + 1
			}
			cur.WriteByte(' ')
		case c == '\'' || c == '"':
			cur.WriteByte(c)
			for i++; i < len(sql); i++ {
				cur.WriteByte(sql[i])
				if sql[i] == c {
					if i+1 < len(sql) && sql[i+1] == c { // doubled quote is an escape
						i++
						cur.WriteByte(c)
						continue
					}
					break
				}
			}
		case c == ';':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return statements
}
