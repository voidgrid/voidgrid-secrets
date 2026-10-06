package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

func TestAPIRevealRequiresValidToken(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	owner, err := e.users.CreateWithPassword(ctx, "api-test-user", "x")
	if err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}
	created, err := e.secrets.Create(ctx, model.OwnerUser, owner.ID, "db-password", []byte("hunter2"), owner.ID)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d", created.ID), nil)
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestAPIRevealRequiresReadACL(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	owner, err := e.users.CreateWithPassword(ctx, "api-test-user", "x")
	if err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}
	created, err := e.secrets.Create(ctx, model.OwnerUser, owner.ID, "db-password", []byte("hunter2"), owner.ID)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	plaintext, _, err := e.tokens.Create(ctx, "no-acl-token", owner.ID, nil)
	if err != nil {
		t.Fatalf("tokens.Create: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d", created.ID), nil)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestAPIRevealSucceedsWithACL(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	owner, err := e.users.CreateWithPassword(ctx, "api-test-user", "x")
	if err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}
	created, err := e.secrets.Create(ctx, model.OwnerUser, owner.ID, "db-password", []byte("hunter2"), owner.ID)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	plaintext, mt, err := e.tokens.Create(ctx, "reader", owner.ID, nil)
	if err != nil {
		t.Fatalf("tokens.Create: %v", err)
	}
	if err := e.tokens.AddACL(ctx, mt.ID, "secret", created.ID, "read", ""); err != nil {
		t.Fatalf("AddACL: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d", created.ID), nil)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Value != "hunter2" {
		t.Fatalf("got value %q, want %q", body.Value, "hunter2")
	}
}

func TestAPIUpdateRequiresWriteNotReadACL(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	owner, err := e.users.CreateWithPassword(ctx, "api-test-user", "x")
	if err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}
	created, err := e.secrets.Create(ctx, model.OwnerUser, owner.ID, "db-password", []byte("hunter2"), owner.ID)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	plaintext, mt, err := e.tokens.Create(ctx, "read-only", owner.ID, nil)
	if err != nil {
		t.Fatalf("tokens.Create: %v", err)
	}
	if err := e.tokens.AddACL(ctx, mt.ID, "secret", created.ID, "read", ""); err != nil {
		t.Fatalf("AddACL: %v", err)
	}

	body := strings.NewReader(`{"value":"new-value"}`)
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", created.ID), body)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestAPIUpdateSucceedsWithWriteACLAndRotatesValue(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	owner, err := e.users.CreateWithPassword(ctx, "api-test-user", "x")
	if err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}
	created, err := e.secrets.Create(ctx, model.OwnerUser, owner.ID, "db-password", []byte("hunter2"), owner.ID)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	plaintext, mt, err := e.tokens.Create(ctx, "writer", owner.ID, nil)
	if err != nil {
		t.Fatalf("tokens.Create: %v", err)
	}
	if err := e.tokens.AddACL(ctx, mt.ID, "secret", created.ID, "write", ""); err != nil {
		t.Fatalf("AddACL: %v", err)
	}

	body := strings.NewReader(`{"value":"rotated-value"}`)
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", created.ID), body)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	revealed, err := e.secrets.Reveal(ctx, created.ID)
	if err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	if string(revealed) != "rotated-value" {
		t.Fatalf("got revealed value %q, want %q", revealed, "rotated-value")
	}
}

func TestAPIRevealSucceedsWithSessionOwnership(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	owner, err := e.users.CreateWithPassword(ctx, "session-owner", "x")
	if err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}
	created, err := e.secrets.Create(ctx, model.OwnerUser, owner.ID, "db-password", []byte("hunter2"), owner.ID)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	sessionToken, _, err := e.sessions.Create(ctx, owner.ID, gosession.DefaultTTL)
	if err != nil {
		t.Fatalf("sessions.Create: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d", created.ID), nil)
	req.AddCookie(&http.Cookie{Name: gosession.CookieName, Value: sessionToken}) //nolint:gosec // request cookie in a test; Secure/HttpOnly/SameSite are response-cookie attributes and don't apply here
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestAPIRevealDeniedForUnrelatedSessionUser(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	owner, err := e.users.CreateWithPassword(ctx, "session-owner-2", "x")
	if err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}
	stranger, err := e.users.CreateWithPassword(ctx, "session-stranger", "x")
	if err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}
	created, err := e.secrets.Create(ctx, model.OwnerUser, owner.ID, "db-password", []byte("hunter2"), owner.ID)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	sessionToken, _, err := e.sessions.Create(ctx, stranger.ID, gosession.DefaultTTL)
	if err != nil {
		t.Fatalf("sessions.Create: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d", created.ID), nil)
	req.AddCookie(&http.Cookie{Name: gosession.CookieName, Value: sessionToken}) //nolint:gosec // request cookie in a test; Secure/HttpOnly/SameSite are response-cookie attributes and don't apply here
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestAPIOpenAPISpecIsServed(t *testing.T) {
	e := newEnv(t, true)

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "voidgrid-secrets API") {
		t.Fatalf("expected OpenAPI spec to mention the API title, body: %s", rec.Body.String())
	}
}

func TestAPIRefusesCrossOriginSessionRequests(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	admin, err := e.users.CreateWithPassword(ctx, "coop-admin", "x")
	if err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}
	if err := e.users.PromoteToAdmin(ctx, admin.ID); err != nil {
		t.Fatalf("PromoteToAdmin: %v", err)
	}
	sessionToken, _, err := e.sessions.Create(ctx, admin.ID, gosession.DefaultTTL)
	if err != nil {
		t.Fatalf("sessions.Create: %v", err)
	}
	_, mt, err := e.tokens.Create(ctx, "victim", admin.ID, nil)
	if err != nil {
		t.Fatalf("tokens.Create: %v", err)
	}

	revoke := func(fetchSite string) int {
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/admin/tokens/%d/revoke", mt.ID), nil)
		req.AddCookie(&http.Cookie{Name: gosession.CookieName, Value: sessionToken}) //nolint:gosec // request cookie in a test; Secure/HttpOnly/SameSite are response-cookie attributes and don't apply here
		req.Header.Set("Sec-Fetch-Site", fetchSite)
		rec := httptest.NewRecorder()
		e.handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := revoke("same-site"); code != http.StatusForbidden {
		t.Fatalf("same-site revoke: status = %d, want 403", code)
	}
	tokens, err := e.tokens.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(tokens) != 1 || tokens[0].RevokedAt != nil {
		t.Fatal("token was revoked by a refused cross-origin request")
	}
	if code := revoke("same-origin"); code >= 300 {
		t.Fatalf("same-origin revoke: status = %d, want success", code)
	}
}
