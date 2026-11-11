package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
)

// Unauthenticated failures can't grow the log without bound: past the
// per-minute cap they're dropped and counted, and nothing else is.
func TestAuditLogCapsUnauthenticatedFailures(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "voidgrid.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	repo := NewAuditRepo(db)
	clock := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	repo.now = func() time.Time { return clock }

	count := func(action string) int {
		t.Helper()
		var n int
		if err := db.SQL().QueryRow(`SELECT count(*) FROM audit_log WHERE action = ?`, action).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	failure := audit.Event{Actor: audit.Anonymous(), Action: audit.TokenAuthFailed, ResourceType: "token"}

	for i := 0; i < anonymousFailuresPerMinute+40; i++ {
		if err := repo.Log(ctx, failure); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(audit.TokenAuthFailed); n != anonymousFailuresPerMinute {
		t.Fatalf("recorded %d failures in one minute, want %d", n, anonymousFailuresPerMinute)
	}

	// Everything else is still recorded while the cap is hit: reveals,
	// and what an unauthenticated request can't cause at will.
	for _, e := range []audit.Event{
		{Actor: audit.Token(1), Action: audit.SecretReveal, ResourceType: "secret", ResourceID: 1},
		{Actor: audit.Anonymous(), Action: audit.RecoveryStarted, ResourceType: "user"},
	} {
		if err := repo.Log(ctx, e); err != nil {
			t.Fatal(err)
		}
		if count(e.Action) != 1 {
			t.Fatalf("%s was dropped while the failure cap was hit", e.Action)
		}
	}

	// The next minute records again, and says how many were dropped.
	clock = clock.Add(time.Minute)
	if err := repo.Log(ctx, failure); err != nil {
		t.Fatal(err)
	}
	if n := count(audit.TokenAuthFailed); n != anonymousFailuresPerMinute+1 {
		t.Fatalf("after a minute: %d failures recorded, want %d", n, anonymousFailuresPerMinute+1)
	}
	var meta string
	if err := db.SQL().QueryRow(`SELECT metadata FROM audit_log WHERE action = ?`, audit.AuditSuppressed).Scan(&meta); err != nil {
		t.Fatalf("no audit_suppressed entry: %v", err)
	}
	if meta != `{"dropped":"40","per_minute_limit":"60"}` {
		t.Fatalf("audit_suppressed metadata = %s", meta)
	}
}
