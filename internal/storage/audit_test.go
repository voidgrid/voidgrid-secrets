package storage_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
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

func TestAuditLogRecordsFiltersAndPages(t *testing.T) {
	db, _ := newTestDB(t)
	ctx := context.Background()
	secret, err := storage.NewSecretRepo(db, make([]byte, crypto.KeySize)).Create(ctx, "audited-secret", []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	_, mt, err := storage.NewTokenRepo(db).Create(ctx, "audited-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	repo := storage.NewAuditRepo(db)

	events := []audit.Event{
		{Actor: audit.User(1), Action: audit.SecretReveal, ResourceType: "secret", ResourceID: secret.ID},
		{Actor: audit.Anonymous(), Action: audit.LoginFailed, ResourceType: "user", Details: map[string]string{"reason": "wrong password"}},
		{Actor: audit.User(1), Action: audit.TokenGrant, ResourceType: "token", ResourceID: mt.ID},
		{Actor: audit.Token(mt.ID), Action: audit.SecretReveal, ResourceType: "secret", ResourceID: secret.ID},
		{Actor: audit.System(), Action: audit.BreakGlassIssued, ResourceType: "user", ResourceID: 1},
	}
	reqCtx := requestContext(t)
	for _, e := range events {
		if err := repo.Log(reqCtx, e); err != nil {
			t.Fatalf("Log %s: %v", e.Action, err)
		}
	}

	all, err := repo.List(ctx, storage.AuditFilter{})
	if err != nil || len(all) != 5 {
		t.Fatalf("List = %d, %v; want 5", len(all), err)
	}
	failed := all[3]
	if failed.Details["reason"] != "wrong password" || failed.Details["ip"] != "192.0.2.10" || failed.Details["forwarded_for"] != "198.51.100.7" {
		t.Fatalf("details = %v", failed.Details)
	}
	tokenReveal := all[1]
	if tokenReveal.ActorName != "audited-token" || tokenReveal.ResourceName != "audited-secret" {
		t.Fatalf("names = %q / %q", tokenReveal.ActorName, tokenReveal.ResourceName)
	}

	if reveals, _ := repo.List(ctx, storage.AuditFilter{Action: audit.SecretReveal}); len(reveals) != 2 {
		t.Fatalf("action filter: %d, want 2", len(reveals))
	}
	// The token filter matches the token acting and being acted on.
	if byToken, _ := repo.List(ctx, storage.AuditFilter{TokenID: mt.ID}); len(byToken) != 2 {
		t.Fatalf("token filter: %d, want 2", len(byToken))
	}

	page1, _ := repo.List(ctx, storage.AuditFilter{Limit: 3})
	page2, _ := repo.List(ctx, storage.AuditFilter{Limit: 3, BeforeID: page1[2].ID})
	if len(page1) != 3 || len(page2) != 2 || page2[1].ID != all[4].ID {
		t.Fatalf("paging: %d then %d", len(page1), len(page2))
	}
}

func TestAuditPruneDeletesOnlyOldEntries(t *testing.T) {
	db, baseURL := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewAuditRepo(db)
	if err := repo.Log(ctx, audit.Event{Actor: audit.User(1), Action: audit.Login, ResourceType: "user"}); err != nil {
		t.Fatal(err)
	}
	rawExec(t, baseURL, `INSERT INTO audit_log (actor_type, actor_id, action, resource_type, created_at)
		VALUES ('user', 1, 'login', 'user', '2020-01-01T00:00:00.000Z')`)

	n, err := repo.Prune(ctx, time.Now().Add(-14*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("Prune = %d, %v; want 1", n, err)
	}
	if left, _ := repo.List(ctx, storage.AuditFilter{}); len(left) != 1 {
		t.Fatalf("entries left = %d, want 1", len(left))
	}
}
