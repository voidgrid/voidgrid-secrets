package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

func TestAuditLogCapturesActionsAndIsSessionOnly(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	cookie := ownerCookie(t, e)
	secret, err := e.secrets.Create(ctx, "audited", []byte("s3cr3t-audit-value"))
	if err != nil {
		t.Fatal(err)
	}

	// A failed login, a token created and granted through the API, a
	// reveal by that token, a reveal it isn't allowed, and a bad token.
	doJSON(t, e.handler, http.MethodPost, "/api/v1/auth/login", `{"username":"owner","password":"wrong-password-xx","totp_code":"000000"}`, nil)
	created := doJSON(t, e.handler, http.MethodPost, "/api/v1/tokens", `{"description":"audited-token"}`, cookie)
	var tok struct {
		Token    string `json:"token"`
		Metadata struct {
			ID int64 `json:"id"`
		} `json:"metadata"`
	}
	if err := json.NewDecoder(created.Body).Decode(&tok); err != nil || tok.Token == "" {
		t.Fatalf("create token: %v, %s", err, created.Body.String())
	}
	if rec := doJSON(t, e.handler, http.MethodPost, fmt.Sprintf("/api/v1/tokens/%d/grants", tok.Metadata.ID),
		fmt.Sprintf(`{"secret_id":%d,"permission":"read"}`, secret.ID), cookie); rec.Code >= 300 {
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

	list := func(query string, c *http.Cookie, bearer string) (int, auditListResponse) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit"+query, nil)
		if c != nil {
			req.AddCookie(c)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		e.handler.ServeHTTP(rec, req)
		var body auditListResponse
		_ = json.NewDecoder(rec.Body).Decode(&body)
		return rec.Code, body
	}

	if code, _ := list("", nil, tok.Token); code != http.StatusUnauthorized {
		t.Fatalf("a machine token read the audit log: %d", code)
	}
	code, all := list("", cookie, "")
	if code != http.StatusOK {
		t.Fatalf("list: %d", code)
	}
	seen := map[string]bool{}
	for _, en := range all.Entries {
		seen[en.Action] = true
		for k, v := range en.Details {
			if strings.Contains(v, tok.Token) || strings.Contains(v, "s3cr3t-audit-value") {
				t.Fatalf("audit detail %s=%q leaks a token or value", k, v)
			}
		}
	}
	for _, want := range []string{"login_failed", "token_create", "token_grant", "reveal", "access_denied", "token_auth_failed"} {
		if !seen[want] {
			t.Errorf("no %s entry; got %v", want, seen)
		}
	}

	_, byToken := list(fmt.Sprintf("?action=reveal&token_id=%d", tok.Metadata.ID), cookie, "")
	if len(byToken.Entries) != 1 || byToken.Entries[0].ResourceID != secret.ID || byToken.Entries[0].ResourceName != "audited" {
		t.Fatalf("token's reveals = %+v", byToken.Entries)
	}
	_, fails := list("?action=login_failed", cookie, "")
	if len(fails.Entries) != 1 || fails.Entries[0].Details["reason"] != "wrong password" || fails.Entries[0].ActorType != "anonymous" {
		t.Fatalf("login_failed = %+v", fails.Entries)
	}
}
