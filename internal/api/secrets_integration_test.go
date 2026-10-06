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

func bearerRequest(t *testing.T, e env, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

// A token reaches only what it's granted: read grants read, write grants
// read and update, and nothing grants listing, creating, renaming or
// deleting.
func TestTokenAccessFollowsGrants(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	readable, err := e.secrets.Create(ctx, "readable", []byte("r-value"))
	if err != nil {
		t.Fatal(err)
	}
	writable, err := e.secrets.Create(ctx, "writable", []byte("w-value"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := e.secrets.Create(ctx, "other", []byte("not-granted"))
	if err != nil {
		t.Fatal(err)
	}
	token, mt, err := e.tokens.Create(ctx, "svc", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.tokens.AddGrant(ctx, mt.ID, readable.ID, "read", ""); err != nil {
		t.Fatal(err)
	}
	if err := e.tokens.AddGrant(ctx, mt.ID, writable.ID, "write", ""); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, method, path, body string
		want                     int
	}{
		{"read granted", "GET", fmt.Sprintf("/api/v1/secrets/%d", readable.ID), "", 200},
		{"read via write grant", "GET", fmt.Sprintf("/api/v1/secrets/%d", writable.ID), "", 200},
		{"read ungranted", "GET", fmt.Sprintf("/api/v1/secrets/%d", other.ID), "", 403},
		{"update with read grant", "PUT", fmt.Sprintf("/api/v1/secrets/%d", readable.ID), `{"value":"x"}`, 403},
		{"update with write grant", "PUT", fmt.Sprintf("/api/v1/secrets/%d", writable.ID), `{"value":"rotated"}`, 200},
		{"list", "GET", "/api/v1/secrets", "", 403},
		{"create", "POST", "/api/v1/secrets", `{"name":"n","value":"v"}`, 403},
		{"rename", "PUT", fmt.Sprintf("/api/v1/secrets/%d/name", writable.ID), `{"name":"renamed"}`, 403},
		{"delete", "DELETE", fmt.Sprintf("/api/v1/secrets/%d", writable.ID), "", 403},
		{"manage tokens", "GET", "/api/v1/tokens", "", 401},
	}
	for _, c := range cases {
		if rec := bearerRequest(t, e, c.method, c.path, c.body, token); rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d; body=%s", c.name, rec.Code, c.want, rec.Body.String())
		}
	}
	if got, _ := e.secrets.Reveal(ctx, writable.ID); string(got) != "rotated" {
		t.Fatalf("write grant didn't update the value: %q", got)
	}
	if rec := bearerRequest(t, e, "GET", fmt.Sprintf("/api/v1/secrets/%d", readable.ID), "", "vgs_bogus"); rec.Code != 401 {
		t.Fatalf("bogus token: %d", rec.Code)
	}
}

// The signed-in account can do everything to a secret.
func TestOwnerSecretLifecycleOverAPI(t *testing.T) {
	e := newEnv(t, true)
	cookie := ownerCookie(t, e)

	rec := doJSON(t, e.handler, "POST", "/api/v1/secrets", `{"name":"db-password","value":"v1"}`, cookie)
	var created struct {
		ID int64 `json:"id"`
	}
	if rec.Code != 200 || json.NewDecoder(rec.Body).Decode(&created) != nil {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, e.handler, "POST", "/api/v1/secrets", `{"name":"db-password","value":"x"}`, cookie); rec.Code != 409 {
		t.Fatalf("duplicate name: %d", rec.Code)
	}
	base := fmt.Sprintf("/api/v1/secrets/%d", created.ID)
	if rec := doJSON(t, e.handler, "PUT", base, `{"value":"v2"}`, cookie); rec.Code != 200 {
		t.Fatalf("update: %d", rec.Code)
	}
	if rec := doJSON(t, e.handler, "PUT", base+"/name", `{"name":"pg-password"}`, cookie); rec.Code != 200 {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, e.handler, "GET", base, "", cookie)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"v2"`) {
		t.Fatalf("reveal: %d %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, e.handler, "GET", "/api/v1/secrets", "", cookie)
	if !strings.Contains(rec.Body.String(), "pg-password") || strings.Contains(rec.Body.String(), "v2") {
		t.Fatalf("list should show names, never values: %s", rec.Body.String())
	}
	if rec := doJSON(t, e.handler, "DELETE", base, "", cookie); rec.Code >= 300 {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := doJSON(t, e.handler, "GET", base, "", cookie); rec.Code != 404 {
		t.Fatalf("after delete: %d", rec.Code)
	}
}

func TestAPIOpenAPISpecIsServed(t *testing.T) {
	e := newEnv(t, true)
	rec := doJSON(t, e.handler, "GET", "/openapi.json", "", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "/api/v1/secrets") {
		t.Fatalf("spec: %d", rec.Code)
	}
}

func TestAPIRefusesCrossOriginSessionRequests(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	cookie := ownerCookie(t, e)
	_, mt, err := e.tokens.Create(ctx, "victim", nil)
	if err != nil {
		t.Fatal(err)
	}
	revoke := func(fetchSite string) int {
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/tokens/%d/revoke", mt.ID), nil)
		req.AddCookie(cookie)
		req.Header.Set("Sec-Fetch-Site", fetchSite)
		rec := httptest.NewRecorder()
		e.handler.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := revoke("same-site"); code != http.StatusForbidden {
		t.Fatalf("same-site revoke: %d, want 403", code)
	}
	if got, _ := e.tokens.Get(ctx, mt.ID); got.RevokedAt != nil {
		t.Fatal("token revoked by a refused cross-origin request")
	}
	if code := revoke("same-origin"); code >= 300 {
		t.Fatalf("same-origin revoke: %d", code)
	}
}
