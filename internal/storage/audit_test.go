package storage_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// requestContext returns a context carrying audit.RequestInfo, as
// audit.Middleware would attach for a real request.
func requestContext(t *testing.T) context.Context {
	t.Helper()
	var ctx context.Context
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.10:5555"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	audit.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { ctx = r.Context() })).
		ServeHTTP(httptest.NewRecorder(), req)
	return ctx
}

func TestAuditLogRecordsAndFilters(t *testing.T) {
	db, _ := newTestDB(t)
	ctx := context.Background()
	rootKey := make([]byte, crypto.KeySize)
	user, err := storage.NewUserRepo(db, rootKey).CreateWithPassword(ctx, "audit-user", "x")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := storage.NewSecretRepo(db, rootKey).Create(ctx, model.OwnerUser, user.ID, "audit-secret", []byte("v"), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	repo := storage.NewAuditRepo(db)

	// Every actor type is accepted (migration 0008 widened the CHECK).
	events := []audit.Event{
		{Actor: audit.User(user.ID), Action: audit.SecretReveal, ResourceType: "secret", ResourceID: secret.ID},
		{Actor: audit.Anonymous(), Action: audit.LoginFailed, ResourceType: "user", ResourceID: user.ID, Details: map[string]string{"reason": "wrong password"}},
		{Actor: audit.System(), Action: audit.EncryptionUpgraded, ResourceType: "secret"},
		{Actor: audit.Token(42), Action: audit.SecretReveal, ResourceType: "secret", ResourceID: secret.ID},
	}
	reqCtx := requestContext(t)
	for _, e := range events {
		if err := repo.Log(reqCtx, e); err != nil {
			t.Fatalf("Log %s: %v", e.Action, err)
		}
	}

	all, err := repo.List(ctx, storage.AuditFilter{})
	if err != nil || len(all) != 4 {
		t.Fatalf("List = %d entries, %v; want 4", len(all), err)
	}
	if all[0].Action != audit.SecretReveal || all[0].ActorType != audit.ActorToken {
		t.Fatalf("newest entry = %+v, want the token reveal", all[0])
	}
	failed := all[2]
	if failed.Details["reason"] != "wrong password" || failed.Details["ip"] != "192.0.2.10" || failed.Details["forwarded_for"] != "198.51.100.7" {
		t.Fatalf("details = %v", failed.Details)
	}
	if failed.ResourceName != "audit-user" {
		t.Fatalf("resource name = %q, want audit-user", failed.ResourceName)
	}
	userReveal := all[3]
	if userReveal.ActorName != "audit-user" || userReveal.ResourceName != "audit-secret" {
		t.Fatalf("names = %q / %q", userReveal.ActorName, userReveal.ResourceName)
	}

	reveals, err := repo.List(ctx, storage.AuditFilter{Action: audit.SecretReveal})
	if err != nil || len(reveals) != 2 {
		t.Fatalf("action filter: %d, %v; want 2", len(reveals), err)
	}
	bySecret, err := repo.List(ctx, storage.AuditFilter{ResourceType: "secret", ResourceID: secret.ID, ActorType: audit.ActorUser})
	if err != nil || len(bySecret) != 1 {
		t.Fatalf("resource+actor filter: %d, %v; want 1", len(bySecret), err)
	}

	page1, err := repo.List(ctx, storage.AuditFilter{Limit: 3})
	if err != nil || len(page1) != 3 {
		t.Fatalf("page 1: %d, %v", len(page1), err)
	}
	page2, err := repo.List(ctx, storage.AuditFilter{Limit: 3, BeforeID: page1[2].ID})
	if err != nil || len(page2) != 1 || page2[0].ID != all[3].ID {
		t.Fatalf("page 2: %+v, %v", page2, err)
	}
}
