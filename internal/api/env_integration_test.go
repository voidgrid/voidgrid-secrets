package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

type envResponse struct {
	Secrets []struct {
		ID      int64  `json:"id"`
		Name    string `json:"name"`
		EnvName string `json:"env_name"`
		Value   string `json:"value"`
	} `json:"secrets"`
}

func getEnv(t *testing.T, e env, authHeader string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/env", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	if cookie != nil {
		req.AddCookie(cookie) //nolint:gosec // request cookie in a test; Secure/HttpOnly/SameSite are response-cookie attributes and don't apply here
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

func countTokenReveals(t *testing.T, db *storage.DB, tokenID int64) int64 {
	t.Helper()
	var n int64
	if err := db.SQL().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_log WHERE actor_type = 'token' AND actor_id = ? AND action = 'reveal'`, tokenID).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return n
}

func TestEnvReturnsGrantedSecretsWithNamesAndAudits(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	if _, err := e.users.SetupPassword(ctx, "env-owner", "x"); err != nil {
		t.Fatalf("SetupPassword: %v", err)
	}
	dbPass, err := e.secrets.Create(ctx, "db-password", []byte("pg-value"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	apiKey, err := e.secrets.Create(ctx, "api-key", []byte("key-value"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := e.secrets.Create(ctx, "not-granted", []byte("must-not-appear")); err != nil {
		t.Fatalf("Create: %v", err)
	}

	plaintext, mt, err := e.tokens.Create(ctx, "svc", nil)
	if err != nil {
		t.Fatalf("tokens.Create: %v", err)
	}
	if err := e.tokens.AddGrant(ctx, mt.ID, dbPass.ID, "read", "POSTGRES_PASSWORD"); err != nil {
		t.Fatalf("AddGrant: %v", err)
	}
	if err := e.tokens.AddGrant(ctx, mt.ID, apiKey.ID, "write", ""); err != nil {
		t.Fatalf("AddGrant: %v", err)
	}

	rec := getEnv(t, e, "Bearer "+plaintext, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "must-not-appear") {
		t.Fatal("response included a secret the token was never granted")
	}
	var body envResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := map[string]string{}
	for _, s := range body.Secrets {
		got[s.EnvName] = s.Value
	}
	want := map[string]string{"POSTGRES_PASSWORD": "pg-value", "API_KEY": "key-value"}
	if len(got) != len(want) {
		t.Fatalf("got %d secrets, want %d: %v", len(got), len(want), body.Secrets)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got value %q, want %q", k, got[k], v)
		}
	}

	if n := countTokenReveals(t, e.db, mt.ID); n != 2 {
		t.Fatalf("audit rows for token reveals = %d, want 2", n)
	}
}

func TestEnvRejectsSessionsAndBadTokens(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	owner, err := e.users.SetupPassword(ctx, "env-owner-2", "x")
	if err != nil {
		t.Fatalf("SetupPassword: %v", err)
	}
	sessionToken, _, err := e.sessions.Create(ctx, owner.ID, time.Hour)
	if err != nil {
		t.Fatalf("sessions.Create: %v", err)
	}
	plaintext, mt, err := e.tokens.Create(ctx, "svc", nil)
	if err != nil {
		t.Fatalf("tokens.Create: %v", err)
	}
	if err := e.tokens.Revoke(ctx, mt.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	cases := []struct {
		name   string
		header string
		cookie *http.Cookie
	}{
		{"no credentials", "", nil},
		{"session cookie only", "", &http.Cookie{Name: gosession.CookieName, Value: sessionToken}}, //nolint:gosec // request cookie in a test; Secure/HttpOnly/SameSite are response-cookie attributes and don't apply here
		{"revoked token", "Bearer " + plaintext, nil},
		{"unknown token", "Bearer vgs_does-not-exist", nil},
	}
	for _, c := range cases {
		if rec := getEnv(t, e, c.header, c.cookie); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401; body=%s", c.name, rec.Code, rec.Body.String())
		}
	}
}

func TestEnvWithNoGrantsReturnsEmptyList(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	if _, err := e.users.SetupPassword(ctx, "env-owner-3", "x"); err != nil {
		t.Fatalf("SetupPassword: %v", err)
	}
	plaintext, _, err := e.tokens.Create(ctx, "svc", nil)
	if err != nil {
		t.Fatalf("tokens.Create: %v", err)
	}

	rec := getEnv(t, e, "Bearer "+plaintext, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"secrets":[]`) {
		t.Fatalf("expected an empty secrets list, body=%s", rec.Body.String())
	}
}

func TestEnvRejectsDuplicateNamesWithoutLeakingValues(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	if _, err := e.users.SetupPassword(ctx, "env-owner-4", "x"); err != nil {
		t.Fatalf("SetupPassword: %v", err)
	}
	a, err := e.secrets.Create(ctx, "first", []byte("value-a"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	b, err := e.secrets.Create(ctx, "second", []byte("value-b"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	plaintext, mt, err := e.tokens.Create(ctx, "svc", nil)
	if err != nil {
		t.Fatalf("tokens.Create: %v", err)
	}

	// AddACL refuses collisions, so write the conflicting rows directly, as
	// pre-existing data would look.
	for _, id := range []int64{a.ID, b.ID} {
		if _, err := e.db.SQL().ExecContext(ctx,
			`INSERT INTO machine_token_grants (token_id, secret_id, permission, env_name) VALUES (?, ?, 'read', 'SAME_NAME')`,
			mt.ID, id); err != nil {
			t.Fatalf("insert conflicting grants: %v", err)
		}
	}

	rec := getEnv(t, e, "Bearer "+plaintext, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "SAME_NAME") || strings.Contains(body, "value-a") || strings.Contains(body, "value-b") {
		t.Fatalf("409 body should name the variable and contain no values, got %s", body)
	}
	if n := countTokenReveals(t, e.db, mt.ID); n != 0 {
		t.Fatalf("audit rows = %d, want 0 (nothing was revealed)", n)
	}
}

func getEnvIfNoneMatch(t *testing.T, e env, plaintext, etag string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/env", nil)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

func TestEnvETagSkipsUnchangedPollsWithoutAuditing(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	if _, err := e.users.SetupPassword(ctx, "env-owner-5", "x"); err != nil {
		t.Fatalf("SetupPassword: %v", err)
	}
	first, err := e.secrets.Create(ctx, "first", []byte("v1"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	second, err := e.secrets.Create(ctx, "second", []byte("v2"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	plaintext, mt, err := e.tokens.Create(ctx, "svc", nil)
	if err != nil {
		t.Fatalf("tokens.Create: %v", err)
	}
	if err := e.tokens.AddGrant(ctx, mt.ID, first.ID, "read", ""); err != nil {
		t.Fatalf("AddGrant: %v", err)
	}

	rec := getEnvIfNoneMatch(t, e, plaintext, "")
	etag := rec.Header().Get("ETag")
	if rec.Code != http.StatusOK || etag == "" {
		t.Fatalf("first fetch: status = %d, ETag = %q", rec.Code, etag)
	}

	// Unchanged: 304, no body values, no new audit rows.
	rec = getEnvIfNoneMatch(t, e, plaintext, etag)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("unchanged poll: status = %d, want 304; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "v1") {
		t.Fatal("304 response carried a value")
	}
	if got := rec.Header().Get("ETag"); got != etag {
		t.Fatalf("304 ETag = %q, want %q", got, etag)
	}
	if n := countTokenReveals(t, e.db, mt.ID); n != 1 {
		t.Fatalf("audit rows after unchanged poll = %d, want 1", n)
	}

	// Value update changes the ETag.
	time.Sleep(5 * time.Millisecond)
	if _, err := e.secrets.Update(ctx, first.ID, []byte("v1-new")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	rec = getEnvIfNoneMatch(t, e, plaintext, etag)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "v1-new") {
		t.Fatalf("after update: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	afterUpdate := rec.Header().Get("ETag")
	if afterUpdate == etag {
		t.Fatal("ETag did not change after a value update")
	}

	// A new grant changes the ETag.
	if err := e.tokens.AddGrant(ctx, mt.ID, second.ID, "read", ""); err != nil {
		t.Fatalf("AddGrant: %v", err)
	}
	rec = getEnvIfNoneMatch(t, e, plaintext, afterUpdate)
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") == afterUpdate {
		t.Fatalf("after new grant: status = %d, ETag unchanged = %v", rec.Code, rec.Header().Get("ETag") == afterUpdate)
	}
	if n := countTokenReveals(t, e.db, mt.ID); n != 4 {
		t.Fatalf("audit rows = %d, want 4 (1 + 1 after update + 2 after new grant)", n)
	}

	// Removing a grant changes the ETag too, so the agent drops that file.
	afterGrant := rec.Header().Get("ETag")
	if err := e.tokens.RemoveGrant(ctx, mt.ID, second.ID); err != nil {
		t.Fatalf("RemoveGrant: %v", err)
	}
	rec = getEnvIfNoneMatch(t, e, plaintext, afterGrant)
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") == afterGrant {
		t.Fatalf("after removing a grant: status = %d, ETag unchanged = %v", rec.Code, rec.Header().Get("ETag") == afterGrant)
	}
}
