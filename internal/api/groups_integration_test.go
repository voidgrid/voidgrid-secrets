package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func TestGroupsOverAPI(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	cookie := ownerCookie(t, e)
	a, err := e.secrets.Create(ctx, "a", []byte("1"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.secrets.Create(ctx, "b", []byte("2"))
	if err != nil {
		t.Fatal(err)
	}

	rec := doJSON(t, e.handler, "POST", "/api/v1/groups", `{"name":"arr"}`, cookie)
	var g struct {
		ID        int64   `json:"id"`
		Name      string  `json:"name"`
		SecretIDs []int64 `json:"secret_ids"`
	}
	if rec.Code != 200 || json.NewDecoder(rec.Body).Decode(&g) != nil || g.Name != "arr" || g.SecretIDs == nil {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	base := fmt.Sprintf("/api/v1/groups/%d", g.ID)

	if rec := doJSON(t, e.handler, "POST", "/api/v1/groups", `{"name":"ARR"}`, cookie); rec.Code != 409 {
		t.Fatalf("duplicate name: %d", rec.Code)
	}
	if rec := doJSON(t, e.handler, "POST", "/api/v1/groups", `{"name":"x\ny"}`, cookie); rec.Code != 400 {
		t.Fatalf("control character: %d", rec.Code)
	}
	if rec := doJSON(t, e.handler, "PUT", base+"/members", fmt.Sprintf(`{"secret_ids":[%d,%d]}`, a.ID, b.ID), cookie); rec.Code != 204 {
		t.Fatalf("set members: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, e.handler, "PUT", base+"/members", `{"secret_ids":[9999]}`, cookie); rec.Code != 404 {
		t.Fatalf("unknown secret: %d", rec.Code)
	}
	rec = doJSON(t, e.handler, "GET", base, "", cookie)
	if rec.Code != 200 || json.NewDecoder(rec.Body).Decode(&g) != nil || len(g.SecretIDs) != 2 {
		t.Fatalf("get: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, e.handler, "PUT", base, `{"name":"media"}`, cookie); rec.Code != 200 {
		t.Fatalf("rename: %d", rec.Code)
	}
	if rec := doJSON(t, e.handler, "GET", "/api/v1/groups", "", cookie); rec.Code != 200 || !contains(rec.Body.String(), `"media"`) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}

	// Session-only: a machine token cannot manage groups.
	token, _, err := e.tokens.Create(ctx, "svc", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec := bearerRequest(t, e, "GET", "/api/v1/groups", "", token); rec.Code != 401 {
		t.Fatalf("token on groups: %d, want 401", rec.Code)
	}

	// Deleting a group touches no secret.
	if rec := doJSON(t, e.handler, "DELETE", base, "", cookie); rec.Code != 204 {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := doJSON(t, e.handler, "GET", base, "", cookie); rec.Code != 404 {
		t.Fatalf("get deleted: %d", rec.Code)
	}
	if _, err := e.secrets.Get(ctx, a.ID); err != nil {
		t.Fatalf("group delete removed a secret: %v", err)
	}
	for _, action := range []string{audit.GroupCreate, audit.GroupMembers, audit.GroupRename, audit.GroupDelete} {
		entries, err := storage.NewAuditRepo(e.db).List(ctx, storage.AuditFilter{Action: action, Limit: 10})
		if err != nil || len(entries) != 1 {
			t.Errorf("audit %s = %+v, %v", action, entries, err)
		}
	}
}

func TestSetTokenGrantsOverAPI(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	cookie := ownerCookie(t, e)
	a, _ := e.secrets.Create(ctx, "a-key", []byte("1"))
	b, _ := e.secrets.Create(ctx, "b-key", []byte("2"))
	token, mt, err := e.tokens.Create(ctx, "svc", nil)
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/v1/tokens/%d/grants", mt.ID)
	body := func(entries string) string { return `{"grants":[` + entries + `]}` }
	entry := func(id int64, perm, env string) string {
		return fmt.Sprintf(`{"secret_id":%d,"permission":%q,"env_name":%q}`, id, perm, env)
	}

	if rec := bearerRequest(t, e, "PUT", path, body(""), token); rec.Code != 401 {
		t.Fatalf("a token setting its own grants: %d, want 401", rec.Code)
	}
	if rec := doJSON(t, e.handler, "PUT", path, body(entry(a.ID, "read", "")+","+entry(b.ID, "write", "B")), cookie); rec.Code != 204 {
		t.Fatalf("set: %d %s", rec.Code, rec.Body.String())
	}
	if rec := bearerRequest(t, e, "GET", fmt.Sprintf("/api/v1/secrets/%d", a.ID), "", token); rec.Code != 200 {
		t.Fatalf("granted read: %d", rec.Code)
	}

	for name, c := range map[string]struct {
		body string
		want int
	}{
		"collision":         {body(entry(a.ID, "read", "X") + "," + entry(b.ID, "read", "X")), 409},
		"bad env name":      {body(entry(a.ID, "read", "lower")), 400},
		"unknown secret":    {body(entry(9999, "read", "")), 404},
		"bad permission":    {body(entry(a.ID, "admin", "")), 422},
		"missing grants":    {`{}`, 422}, // must be explicit: "replace everything" is never implied
		"explicit empty":    {body(""), 204},
		"restored after ok": {body(entry(a.ID, "read", "")), 204},
	} {
		if rec := doJSON(t, e.handler, "PUT", path, c.body, cookie); rec.Code != c.want {
			t.Errorf("%s: %d, want %d: %s", name, rec.Code, c.want, rec.Body.String())
		}
	}
	if rec := doJSON(t, e.handler, "PUT", "/api/v1/tokens/9999/grants", body(""), cookie); rec.Code != 404 {
		t.Fatalf("unknown token: %d", rec.Code)
	}
	entries, err := storage.NewAuditRepo(e.db).List(ctx, storage.AuditFilter{Action: audit.TokenGrantsSet, Limit: 10})
	if err != nil || len(entries) < 2 {
		t.Fatalf("audit = %+v, %v", entries, err)
	}
}

func contains(s, sub string) bool { return len(sub) > 0 && len(s) >= len(sub) && indexOf(s, sub) >= 0 }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
