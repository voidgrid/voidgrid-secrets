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
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

type auditListResponse struct {
	Entries []struct {
		ActorType    string            `json:"actor_type"`
		ActorID      int64             `json:"actor_id"`
		Action       string            `json:"action"`
		ResourceType string            `json:"resource_type"`
		ResourceID   int64             `json:"resource_id"`
		ResourceName string            `json:"resource_name"`
		Details      map[string]string `json:"details"`
	} `json:"entries"`
	NextBefore int64 `json:"next_before"`
}

func TestAuditLogCapturesActionsAndIsAdminOnly(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	hash, err := crypto.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := e.users.CreateWithPassword(ctx, "audit-admin", hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.users.PromoteToAdmin(ctx, admin.ID); err != nil {
		t.Fatal(err)
	}
	member, err := e.users.CreateWithPassword(ctx, "audit-member", "x")
	if err != nil {
		t.Fatal(err)
	}
	adminSession, _, err := e.sessions.Create(ctx, admin.ID, gosession.DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	memberSession, _, err := e.sessions.Create(ctx, member.ID, gosession.DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	adminCookie := &http.Cookie{Name: gosession.CookieName, Value: adminSession}   //nolint:gosec // request cookie in a test; Secure/HttpOnly/SameSite are response-cookie attributes and don't apply here
	memberCookie := &http.Cookie{Name: gosession.CookieName, Value: memberSession} //nolint:gosec // request cookie in a test; Secure/HttpOnly/SameSite are response-cookie attributes and don't apply here
	secret, err := e.secrets.Create(ctx, model.OwnerUser, admin.ID, "audited", []byte("s3cr3t-audit-value"), admin.ID)
	if err != nil {
		t.Fatal(err)
	}

	// A failed login, a token created and granted through the API, a
	// reveal by that token, a reveal it isn't allowed, and a bad token.
	doJSON(t, e.handler, http.MethodPost, "/api/v1/auth/login", `{"username":"audit-admin","password":"wrong-password-xx","totp_code":"000000"}`, nil)
	created := doJSON(t, e.handler, http.MethodPost, "/api/v1/admin/tokens", `{"description":"audited-token"}`, adminCookie)
	var tok struct {
		Token    string `json:"token"`
		Metadata struct {
			ID int64 `json:"id"`
		} `json:"metadata"`
	}
	if err := json.NewDecoder(created.Body).Decode(&tok); err != nil || tok.Token == "" {
		t.Fatalf("create token: %v, %s", err, created.Body.String())
	}
	if rec := doJSON(t, e.handler, http.MethodPost, fmt.Sprintf("/api/v1/admin/tokens/%d/acls", tok.Metadata.ID),
		fmt.Sprintf(`{"resource_type":"secret","resource_id":%d,"permission":"read"}`, secret.ID), adminCookie); rec.Code >= 300 {
		t.Fatalf("grant: %d %s", rec.Code, rec.Body.String())
	}
	reveal := func(id int64, bearer string) int {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d", id), nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		rec := httptest.NewRecorder()
		e.handler.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := reveal(secret.ID, tok.Token); code != http.StatusOK {
		t.Fatalf("token reveal: %d", code)
	}
	if code := reveal(secret.ID+1000, tok.Token); code != http.StatusForbidden {
		t.Fatalf("ungranted reveal: %d", code)
	}
	if code := reveal(secret.ID, "vgs_not-a-token"); code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", code)
	}

	list := func(query string, cookie *http.Cookie) (int, auditListResponse) {
		rec := doJSON(t, e.handler, http.MethodGet, "/api/v1/admin/audit"+query, "", cookie)
		var body auditListResponse
		_ = json.NewDecoder(rec.Body).Decode(&body)
		return rec.Code, body
	}

	if code, _ := list("", memberCookie); code != http.StatusForbidden {
		t.Fatalf("non-admin read the audit log: %d", code)
	}
	code, all := list("", adminCookie)
	if code != http.StatusOK {
		t.Fatalf("admin list: %d", code)
	}
	seen := map[string]bool{}
	for _, en := range all.Entries {
		seen[en.Action] = true
	}
	for _, want := range []string{"login_failed", "token_create", "token_grant", "reveal", "access_denied", "token_auth_failed"} {
		if !seen[want] {
			t.Errorf("no %s entry; got %v", want, seen)
		}
	}

	_, reveals := list(fmt.Sprintf("?action=reveal&actor_type=token&actor_id=%d", tok.Metadata.ID), adminCookie)
	if len(reveals.Entries) != 1 || reveals.Entries[0].ResourceID != secret.ID || reveals.Entries[0].ResourceName != "audited" {
		t.Fatalf("filtered reveals = %+v", reveals.Entries)
	}
	_, fails := list("?action=login_failed", adminCookie)
	if len(fails.Entries) != 1 || fails.Entries[0].Details["reason"] != "wrong password" || fails.Entries[0].ActorType != "anonymous" {
		t.Fatalf("login_failed = %+v", fails.Entries)
	}
	for _, en := range all.Entries {
		for k, v := range en.Details {
			if strings.Contains(v, tok.Token) || strings.Contains(v, "s3cr3t-audit-value") {
				t.Fatalf("audit detail %s=%q leaks a token or value", k, v)
			}
		}
	}
}
