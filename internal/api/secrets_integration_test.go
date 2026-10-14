package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
	"github.com/voidgrid/voidgrid-secrets/internal/version"
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
	var spec struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &spec); err != nil || spec.Info.Version != strings.TrimPrefix(version.Version, "v") {
		t.Fatalf("spec version = %q, want the build's version %q (%v)", spec.Info.Version, version.Version, err)
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

// Removing a grant cuts that one secret off the token immediately, leaves
// its other grants alone, is audited, and is session-only.
func TestUngrantOverAPI(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	cookie := ownerCookie(t, e)
	keep, err := e.secrets.Create(ctx, "keep", []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	drop, err := e.secrets.Create(ctx, "drop", []byte("d"))
	if err != nil {
		t.Fatal(err)
	}
	token, mt, err := e.tokens.Create(ctx, "svc", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []int64{keep.ID, drop.ID} {
		if err := e.tokens.AddGrant(ctx, mt.ID, s, "read", ""); err != nil {
			t.Fatal(err)
		}
	}
	path := fmt.Sprintf("/api/v1/tokens/%d/grants/%d", mt.ID, drop.ID)

	if rec := bearerRequest(t, e, "DELETE", path, "", token); rec.Code != 401 {
		t.Fatalf("a token removing its own grant: %d, want 401", rec.Code)
	}
	if rec := bearerRequest(t, e, "GET", fmt.Sprintf("/api/v1/secrets/%d", drop.ID), "", token); rec.Code != 200 {
		t.Fatalf("before removal: %d", rec.Code)
	}
	if rec := doJSON(t, e.handler, "DELETE", path, "", cookie); rec.Code != 204 {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body.String())
	}
	if rec := bearerRequest(t, e, "GET", fmt.Sprintf("/api/v1/secrets/%d", drop.ID), "", token); rec.Code != 403 {
		t.Fatalf("after removal: %d, want 403", rec.Code)
	}
	if rec := bearerRequest(t, e, "GET", fmt.Sprintf("/api/v1/secrets/%d", keep.ID), "", token); rec.Code != 200 {
		t.Fatalf("other grant after removal: %d, want 200", rec.Code)
	}
	if rec := doJSON(t, e.handler, "DELETE", path, "", cookie); rec.Code != 404 {
		t.Fatalf("remove again: %d, want 404", rec.Code)
	}
	if rec := doJSON(t, e.handler, "DELETE", "/api/v1/tokens/9999/grants/1", "", cookie); rec.Code != 404 {
		t.Fatalf("unknown token: %d, want 404", rec.Code)
	}
	entries, err := storage.NewAuditRepo(e.db).List(ctx, storage.AuditFilter{Action: audit.TokenUngrant, Limit: 10})
	if err != nil || len(entries) != 1 || entries[0].ResourceID != mt.ID {
		t.Fatalf("audit entries = %+v, %v", entries, err)
	}
}

// A provisioning token lists and creates secrets and nothing more; a
// plain token still can't, and creating never overwrites.
func TestProvisioningTokenCreatesButNothingElse(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	existing, err := e.secrets.Create(ctx, "existing", []byte("original"))
	if err != nil {
		t.Fatal(err)
	}
	prov, _, err := e.tokens.CreateWith(ctx, "loader", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	plain, _, err := e.tokens.Create(ctx, "plain", nil)
	if err != nil {
		t.Fatal(err)
	}

	rec := bearerRequest(t, e, "POST", "/api/v1/secrets", `{"name":"fresh","value":"v1"}`, prov)
	if rec.Code != 200 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct{ ID int64 }
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == 0 {
		t.Fatalf("create body = %s, %v", rec.Body.String(), err)
	}
	if rec := bearerRequest(t, e, "GET", "/api/v1/secrets", "", prov); rec.Code != 200 || !strings.Contains(rec.Body.String(), "fresh") {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}

	cases := []struct {
		name, method, path, body, token string
		want                            int
	}{
		{"overwrite by name", "POST", "/api/v1/secrets", `{"name":"existing","value":"x"}`, prov, 409},
		{"plain token create", "POST", "/api/v1/secrets", `{"name":"n2","value":"v"}`, plain, 403},
		{"plain token list", "GET", "/api/v1/secrets", "", plain, 403},
		{"reveal", "GET", fmt.Sprintf("/api/v1/secrets/%d", existing.ID), "", prov, 403},
		{"reveal own creation", "GET", fmt.Sprintf("/api/v1/secrets/%d", created.ID), "", prov, 403},
		{"update", "PUT", fmt.Sprintf("/api/v1/secrets/%d", existing.ID), `{"value":"x"}`, prov, 403},
		{"rename", "PUT", fmt.Sprintf("/api/v1/secrets/%d/name", existing.ID), `{"name":"r"}`, prov, 403},
		{"delete", "DELETE", fmt.Sprintf("/api/v1/secrets/%d", existing.ID), "", prov, 403},
		{"manage tokens", "GET", "/api/v1/tokens", "", prov, 401},
		{"grant", "POST", "/api/v1/tokens/1/grants", fmt.Sprintf(`{"secret_id":%d,"permission":"read"}`, existing.ID), prov, 401},
	}
	for _, c := range cases {
		if rec := bearerRequest(t, e, c.method, c.path, c.body, c.token); rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d; body=%s", c.name, rec.Code, c.want, rec.Body.String())
		}
	}
	if v, err := e.secrets.Reveal(ctx, existing.ID); err != nil || string(v) != "original" {
		t.Fatalf("existing value = %q, %v; want unchanged", v, err)
	}
}

// The account can mint a provisioning token over the API.
func TestCreateProvisioningTokenViaAPI(t *testing.T) {
	e := newEnv(t, true)
	cookie := ownerCookie(t, e)
	rec := doJSON(t, e.handler, "POST", "/api/v1/tokens", `{"description":"loader","provision":true}`, cookie)
	if rec.Code != 200 {
		t.Fatalf("create token: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Token    string
		Metadata struct{ Provision bool }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || !out.Metadata.Provision || out.Token == "" {
		t.Fatalf("body = %s, %v", rec.Body.String(), err)
	}
	if rec := bearerRequest(t, e, "POST", "/api/v1/secrets", `{"name":"via-api","value":"v"}`, out.Token); rec.Code != 200 {
		t.Fatalf("create with minted token: %d %s", rec.Code, rec.Body.String())
	}
}
