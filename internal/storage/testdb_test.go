package storage_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// newTestDB opens a fresh SQLite database in a temp directory, applies the
// migrations, and returns it. It is closed when the test completes.
func newTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "voidgrid.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(db.Close)
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

// insertTestUser inserts a minimal user row directly so that foreign keys
// that point at the single account are satisfiable in tests.
func insertTestUser(t *testing.T, db *storage.DB, username string) int64 {
	t.Helper()
	res, err := db.SQL().ExecContext(context.Background(),
		`INSERT INTO users (id, username, auth_method, password_hash, created_at) VALUES (1, ?, 'password_totp', 'x', '2026-01-01T00:00:00.000Z')`, username)
	if err != nil {
		t.Fatalf("insert test user: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
