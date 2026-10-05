package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/rqlite/gorqlite"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// TestTimestampsAreWrittenAtInsertTime guards against relying on the
// migrations' strftime('now') column defaults: rqlite rewrites 'now' when
// it executes the CREATE TABLE, so a row that used the default would carry
// the table's creation time. Rows written a second after migrating must
// carry their own insert time instead.
func TestTimestampsAreWrittenAtInsertTime(t *testing.T) {
	db, baseURL := newTestDB(t)
	ctx := context.Background()
	rootKey := make([]byte, crypto.KeySize)

	time.Sleep(1100 * time.Millisecond)
	notBefore := time.Now().Add(-100 * time.Millisecond)

	users := storage.NewUserRepo(db, rootKey)
	user, err := users.CreateWithPassword(ctx, "ts-user", "x")
	if err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}
	if _, _, err := users.GetOrCreateUser(ctx, "ts-subject", "ts-oidc"); err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	group, err := storage.NewGroupRepo(db).Create(ctx, "ts-group", "")
	if err != nil {
		t.Fatalf("group Create: %v", err)
	}
	secret, err := storage.NewSecretRepo(db, rootKey).Create(ctx, model.OwnerUser, user.ID, "ts-secret", []byte("v"), user.ID)
	if err != nil {
		t.Fatalf("secret Create: %v", err)
	}
	if err := storage.NewShareRepo(db).Create(ctx, secret.ID, model.OwnerGroup, group.ID, "read", user.ID); err != nil {
		t.Fatalf("share Create: %v", err)
	}
	if _, _, err := storage.NewTokenRepo(db).Create(ctx, "ts-token", user.ID, nil); err != nil {
		t.Fatalf("token Create: %v", err)
	}
	if _, _, err := storage.NewSessionRepo(db).Create(ctx, user.ID, time.Hour); err != nil {
		t.Fatalf("session Create: %v", err)
	}
	if err := storage.NewAuditRepo(db).Log(ctx, "user", user.ID, "reveal", "secret", secret.ID); err != nil {
		t.Fatalf("audit Log: %v", err)
	}
	if err := storage.NewRecoveryCodeRepo(db).ReplaceForUser(ctx, user.ID, []string{"hash"}); err != nil {
		t.Fatalf("ReplaceForUser: %v", err)
	}
	if err := storage.NewAuthConfigRepo(db, rootKey).CompletePasswordTOTP(ctx); err != nil {
		t.Fatalf("CompletePasswordTOTP: %v", err)
	}
	notAfter := time.Now().Add(time.Second)

	conn, err := gorqlite.Open(baseURL)
	if err != nil {
		t.Fatalf("open raw connection: %v", err)
	}
	defer conn.Close()

	columns := map[string]string{
		"users":          "created_at",
		"groups":         "created_at",
		"secrets":        "created_at",
		"secret_shares":  "granted_at",
		"machine_tokens": "created_at",
		"sessions":       "created_at",
		"audit_log":      "created_at",
		"recovery_codes": "created_at",
		"auth_config":    "completed_at",
	}
	for table, column := range columns {
		qr, err := conn.QueryOneContext(ctx, "SELECT "+column+" FROM "+table) //nolint:gosec // table/column names come from the fixed map above
		if err != nil {
			t.Fatalf("query %s.%s: %v", table, column, err)
		}
		rows := 0
		for qr.Next() {
			rows++
			var raw string
			if err := qr.Scan(&raw); err != nil {
				t.Fatalf("scan %s.%s: %v", table, column, err)
			}
			got, err := time.Parse("2006-01-02T15:04:05.999Z", raw)
			if err != nil {
				t.Fatalf("parse %s.%s %q: %v", table, column, raw, err)
			}
			if got.Before(notBefore) || got.After(notAfter) {
				t.Errorf("%s.%s = %s, want a time between %s and %s (a frozen column default?)",
					table, column, raw, notBefore.UTC().Format(time.RFC3339Nano), notAfter.UTC().Format(time.RFC3339Nano))
			}
		}
		if rows == 0 {
			t.Errorf("%s: no rows written", table)
		}
	}
}
