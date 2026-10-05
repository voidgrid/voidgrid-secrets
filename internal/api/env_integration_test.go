package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rqlite/gorqlite"

	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
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

func countTokenReveals(t *testing.T, baseURL string, tokenID int64) int64 {
	t.Helper()
	conn, err := gorqlite.Open(baseURL)
	if err != nil {
		t.Fatalf("open raw connection: %v", err)
	}
	defer conn.Close()
	qr, err := conn.QueryOneParameterizedContext(context.Background(), gorqlite.ParameterizedStatement{
		Query:     `SELECT COUNT(*) FROM audit_log WHERE actor_type = 'token' AND actor_id = ? AND action = 'reveal'`,
		Arguments: []interface{}{tokenID},
	})
	if err != nil || !qr.Next() {
		t.Fatalf("count audit rows: %v", err)
	}
	var n int64
	if err := qr.Scan(&n); err != nil {
		t.Fatalf("scan audit count: %v", err)
	}
	return n
}

func TestEnvReturnsGrantedSecretsWithNamesAndAudits(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	owner, err := e.users.CreateWithPassword(ctx, "env-owner", "x")
	if err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}
	dbPass, err := e.secrets.Create(ctx, model.OwnerUser, owner.ID, "db-password", []byte("pg-value"), owner.ID)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	apiKey, err := e.secrets.Create(ctx, model.OwnerUser, owner.ID, "api-key", []byte("key-value"), owner.ID)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := e.secrets.Create(ctx, model.OwnerUser, owner.ID, "not-granted", []byte("must-not-appear"), owner.ID); err != nil {
		t.Fatalf("Create: %v", err)
	}

	plaintext, mt, err := e.tokens.Create(ctx, "svc", owner.ID, nil)
	if err != nil {
		t.Fatalf("tokens.Create: %v", err)
	}
	if err := e.tokens.AddACL(ctx, mt.ID, "secret", dbPass.ID, "read", "POSTGRES_PASSWORD"); err != nil {
		t.Fatalf("AddACL: %v", err)
	}
	if err := e.tokens.AddACL(ctx, mt.ID, "secret", apiKey.ID, "write", ""); err != nil {
		t.Fatalf("AddACL: %v", err)
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

	if n := countTokenReveals(t, e.baseURL, mt.ID); n != 2 {
		t.Fatalf("audit rows for token reveals = %d, want 2", n)
	}
}

func TestEnvRejectsSessionsAndBadTokens(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	owner, err := e.users.CreateWithPassword(ctx, "env-owner-2", "x")
	if err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}
	sessionToken, _, err := e.sessions.Create(ctx, owner.ID, time.Hour)
	if err != nil {
		t.Fatalf("sessions.Create: %v", err)
	}
	plaintext, mt, err := e.tokens.Create(ctx, "svc", owner.ID, nil)
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

	owner, err := e.users.CreateWithPassword(ctx, "env-owner-3", "x")
	if err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}
	plaintext, _, err := e.tokens.Create(ctx, "svc", owner.ID, nil)
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

	owner, err := e.users.CreateWithPassword(ctx, "env-owner-4", "x")
	if err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}
	a, err := e.secrets.Create(ctx, model.OwnerUser, owner.ID, "first", []byte("value-a"), owner.ID)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	b, err := e.secrets.Create(ctx, model.OwnerUser, owner.ID, "second", []byte("value-b"), owner.ID)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	plaintext, mt, err := e.tokens.Create(ctx, "svc", owner.ID, nil)
	if err != nil {
		t.Fatalf("tokens.Create: %v", err)
	}

	// AddACL refuses collisions, so write the conflicting rows directly, as
	// pre-existing data would look.
	conn, err := gorqlite.Open(e.baseURL)
	if err != nil {
		t.Fatalf("open raw connection: %v", err)
	}
	defer conn.Close()
	stmts := []gorqlite.ParameterizedStatement{}
	for _, id := range []int64{a.ID, b.ID} {
		stmts = append(stmts, gorqlite.ParameterizedStatement{
			Query:     `INSERT INTO machine_token_acls (token_id, resource_type, resource_id, permission, env_name) VALUES (?, 'secret', ?, 'read', 'SAME_NAME')`,
			Arguments: []interface{}{mt.ID, id},
		})
	}
	if wr, err := conn.WriteParameterizedContext(ctx, stmts); err != nil || wr[0].Err != nil || wr[1].Err != nil {
		t.Fatalf("insert conflicting grants: %v", err)
	}

	rec := getEnv(t, e, "Bearer "+plaintext, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "SAME_NAME") || strings.Contains(body, "value-a") || strings.Contains(body, "value-b") {
		t.Fatalf("409 body should name the variable and contain no values, got %s", body)
	}
	if n := countTokenReveals(t, e.baseURL, mt.ID); n != 0 {
		t.Fatalf("audit rows = %d, want 0 (nothing was revealed)", n)
	}
}
