package storage_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/rqlite/gorqlite"

	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// newTestDB starts a fresh single-node rqlited instance in a temp directory
// on free ports, applies migrations, and returns a connected *storage.DB.
// The instance is stopped and its data directory removed when the test (or
// its subtests) complete via t.Cleanup.
//
// This talks to a real rqlite binary rather than a mock, since SQLite
// dialect quirks and rqlite's HTTP wire format (see storage package docs on
// BLOB handling) matter for correctness here.
func newTestDB(t *testing.T) (*storage.DB, string) {
	t.Helper()

	if _, err := exec.LookPath("rqlited"); err != nil {
		t.Skip("rqlited not found in PATH; skipping integration test")
	}

	httpPort := freePort(t)
	raftPort := freePort(t)
	dataDir := t.TempDir()

	httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)
	cmd := exec.Command("rqlited", //nolint:gosec // fixed binary name + test-generated args, not attacker-controlled
		"-fk",
		"-http-addr", httpAddr,
		"-raft-addr", fmt.Sprintf("127.0.0.1:%d", raftPort),
		dataDir,
	)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		t.Fatalf("start rqlited: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	baseURL := "http://" + httpAddr
	waitForReady(t, baseURL)

	db, err := storage.Open(baseURL)
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(db.Close)

	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	return db, baseURL
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForReady(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/readyz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("rqlited at %s did not become ready in time", baseURL)
}

// insertTestUser inserts a minimal user row directly (bypassing any
// repository, which doesn't exist yet) so that secrets.created_by's foreign
// key constraint is satisfiable in tests. It opens its own connection to
// baseURL rather than reusing storage.DB, since storage.DB intentionally
// doesn't expose raw SQL access outside the package.
func insertTestUser(t *testing.T, baseURL, username string) int64 {
	t.Helper()

	conn, err := gorqlite.Open(baseURL)
	if err != nil {
		t.Fatalf("open raw connection: %v", err)
	}
	defer conn.Close()

	wr, err := conn.WriteParameterizedContext(context.Background(), []gorqlite.ParameterizedStatement{
		{
			Query:     `INSERT INTO users (id, username, auth_method, password_hash, created_at) VALUES (1, ?, 'password_totp', 'x', '2026-01-01T00:00:00.000Z')`,
			Arguments: []interface{}{username},
		},
	})
	if err != nil || wr[0].Err != nil {
		t.Fatalf("insert test user: err=%v writeErr=%v", err, wr[0].Err)
	}
	return wr[0].LastInsertID
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
