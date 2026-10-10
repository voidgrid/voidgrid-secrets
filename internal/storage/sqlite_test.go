package storage_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func TestOpenCreatesAPrivateFileAndEnforcesForeignKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "voidgrid.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("database file mode = %v, %v; want 0600", st.Mode().Perm(), err)
	}
	// A grant pointing at nothing must be refused: foreign keys are on.
	_, err = db.SQL().ExecContext(context.Background(),
		`INSERT INTO machine_token_grants (token_id, secret_id, permission) VALUES (999, 999, 'read')`)
	if err == nil || !strings.Contains(err.Error(), "FOREIGN KEY") {
		t.Fatalf("dangling grant = %v, want a foreign key error", err)
	}
	// Re-running migrations is a no-op.
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

func TestMigrateIsAtomicPerFile(t *testing.T) {
	db := newTestDB(t)
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil || n < 2 {
		t.Fatalf("schema_migrations rows = %d, %v; want every embedded migration recorded", n, err)
	}
	var tables int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('secrets','secret_groups','secret_group_members','machine_token_grants')`).Scan(&tables); err != nil || tables != 4 {
		t.Fatalf("expected tables = %d, %v", tables, err)
	}
}

func TestBackupIsAConsistentStandaloneCopy(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	s := createTestSecret(t, db, "kept-in-backup")
	dir := t.TempDir()
	out := filepath.Join(dir, "backup.db")
	if err := db.BackupTo(ctx, out); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}
	if st, err := os.Stat(out); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %v, %v", st.Mode().Perm(), err)
	}
	if err := db.BackupTo(ctx, out); err == nil {
		t.Fatal("BackupTo must refuse to overwrite an existing file")
	}

	// Changes after the backup are not in it, and it opens on its own.
	createTestSecret(t, db, "created-after")
	copyDB, err := storage.Open(out)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer copyDB.Close()
	var names []string
	rows, err := copyDB.SQL().QueryContext(ctx, `SELECT name FROM secrets ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	if fmt.Sprint(names) != "[kept-in-backup]" {
		t.Fatalf("backup holds %v (secret %d expected only the first)", names, s.ID)
	}
	if problems, err := copyDB.CheckIntegrity(ctx); err != nil || len(problems) != 0 {
		t.Fatalf("backup integrity = %v, %v", problems, err)
	}
}

func TestCheckLegacyRefusesAnRqliteDirectoryWithoutADatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "voidgrid.db")
	if err := storage.CheckLegacy(path); err != nil {
		t.Fatalf("empty directory: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "rqlite"), 0o750); err != nil {
		t.Fatal(err)
	}
	err := storage.CheckLegacy(path)
	if err == nil || !strings.Contains(err.Error(), "Moving from rqlite") {
		t.Fatalf("legacy directory = %v, want a pointer to the migration docs", err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := storage.CheckLegacy(path); err != nil {
		t.Fatalf("with a database present: %v", err)
	}
}

func TestConcurrentUseDoesNotLockOrRace(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := storage.NewTokenRepo(db)
	secrets := make([]int64, 8)
	for i := range secrets {
		secrets[i] = createTestSecret(t, db, fmt.Sprintf("s%d", i)).ID
	}
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				_, mt, err := repo.Create(ctx, fmt.Sprintf("t-%d-%d", g, i), nil)
				if err != nil {
					errs <- err
					return
				}
				if _, err := repo.SetGrants(ctx, mt.ID, []storage.GrantSpec{
					{SecretID: secrets[(g+i)%8], Permission: "read"},
					{SecretID: secrets[(g+i+1)%8], Permission: "write"},
				}); err != nil {
					errs <- err
					return
				}
				if _, err := repo.ListGrants(ctx, mt.ID); err != nil {
					errs <- err
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent use: %v", err)
	}
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM machine_tokens`).Scan(&n); err != nil || n != 120 {
		t.Fatalf("tokens = %d, %v; want 120", n, err)
	}
}

func TestAFailedStatementRollsBackTheWholeWrite(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := storage.NewGroupRepo(db)
	g, err := repo.Create(ctx, "g")
	if err != nil {
		t.Fatal(err)
	}
	s := createTestSecret(t, db, "real")
	if err := repo.SetMembers(ctx, g.ID, []int64{s.ID}); err != nil {
		t.Fatal(err)
	}
	// The second insert refers to a missing secret: the delete before it must roll back too.
	if err := repo.SetMembers(ctx, g.ID, []int64{s.ID, 4242}); err == nil {
		t.Fatal("expected an error")
	}
	got, _ := repo.Get(ctx, g.ID)
	if len(got.SecretIDs) != 1 || got.SecretIDs[0] != s.ID {
		t.Fatalf("members after a failed write = %v", got.SecretIDs)
	}
}

func TestOpenExplainsAnUnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	dir := filepath.Join(t.TempDir(), "d")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "voidgrid.db")
	first, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	// The file exists and is writable, but the directory no longer is.
	for _, f := range []string{path + "-wal", path + "-shm"} {
		_ = os.Remove(f)
	}
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // a directory needs its execute bit; this is a temp dir in a test
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }() //nolint:gosec // restore a temp dir so cleanup can remove it
	_, err = storage.Open(path)
	if err == nil || !strings.Contains(err.Error(), "must be writable by this user") {
		t.Fatalf("Open in a read-only directory = %v, want a hint about writability", err)
	}
}
