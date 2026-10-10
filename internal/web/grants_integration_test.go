package web_test

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func idStr(n int64) string { return strconv.FormatInt(n, 10) }

func TestWebTokenEditorSavesTheWholeSet(t *testing.T) {
	e := newEnv(t)
	completeSetupDirect(t, e)
	cookie := ownerSession(t, e)
	ctx := context.Background()
	a, _ := e.secrets.Create(ctx, "tmdb", []byte("v"))
	b, _ := e.secrets.Create(ctx, "seerr", []byte("v"))
	c, _ := e.secrets.Create(ctx, "other", []byte("v"))
	_, mt, err := e.tokens.Create(ctx, "svc", nil)
	if err != nil {
		t.Fatal(err)
	}
	g, err := e.groups.Create(ctx, "arr")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.groups.SetMembers(ctx, g.ID, []int64{a.ID, b.ID}); err != nil {
		t.Fatal(err)
	}
	path := "/tokens/" + idStr(mt.ID) + "/grants"

	// The page lists every secret once and a quick-select toggle per group.
	page := get(t, e, "/tokens/"+idStr(mt.ID), cookie).Body.String()
	for _, want := range []string{`data-group-members="` + idStr(a.ID) + "," + idStr(b.ID) + `"`, "arr (2)", `name="secret" value="` + idStr(c.ID) + `"`, `placeholder="TMDB"`} {
		if !strings.Contains(page, want) {
			t.Fatalf("editor page lacks %q:\n%s", want, page)
		}
	}
	if strings.Count(page, `name="secret"`) != 3 {
		t.Fatalf("each secret should appear exactly once")
	}

	// Signed out: refused, nothing changes.
	form := url.Values{"secret": {idStr(a.ID)}, "perm_" + idStr(a.ID): {"read"}}
	if rec := doForm(t, e.handler, path, form, nil); rec.Header().Get("Location") != "/login" {
		t.Fatalf("signed-out save: %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	if g, _ := e.tokens.ListGrants(ctx, mt.ID); len(g) != 0 {
		t.Fatalf("a signed-out request changed grants: %+v", g)
	}

	// Tick the group's two secrets, one as write with an explicit name.
	form = url.Values{
		"secret":              {idStr(a.ID), idStr(b.ID)},
		"perm_" + idStr(a.ID): {"read"},
		"perm_" + idStr(b.ID): {"write"},
		"env_" + idStr(a.ID):  {"TMDB_API_KEY"},
		"env_" + idStr(b.ID):  {""},
		"perm_" + idStr(c.ID): {"read"},
		"env_" + idStr(c.ID):  {"IGNORED_UNTICKED"},
	}
	if rec := doForm(t, e.handler, path, form, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	grants, _ := e.tokens.ListGrants(ctx, mt.ID)
	if len(grants) != 2 {
		t.Fatalf("grants = %+v", grants)
	}
	byID := map[int64]string{}
	for _, gr := range grants {
		byID[gr.SecretID] = gr.Permission + "/" + gr.EnvName
	}
	if byID[a.ID] != "read/TMDB_API_KEY" || byID[b.ID] != "write/" {
		t.Fatalf("grants = %v", byID)
	}
	page = get(t, e, "/tokens/"+idStr(mt.ID), cookie).Body.String()
	if !strings.Contains(page, `value="`+idStr(a.ID)+`" data-secret="`+idStr(a.ID)+`" checked`) || !strings.Contains(page, `value="TMDB_API_KEY"`) {
		t.Fatalf("saved state not shown:\n%s", page)
	}

	// A refused save changes nothing and keeps what was typed.
	form = url.Values{
		"secret":              {idStr(a.ID), idStr(c.ID)},
		"perm_" + idStr(a.ID): {"read"}, "perm_" + idStr(c.ID): {"read"},
		"env_" + idStr(a.ID): {"CLASH"}, "env_" + idStr(c.ID): {"CLASH"},
	}
	rec := doForm(t, e.handler, path, form, cookie)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "CLASH") || !strings.Contains(rec.Body.String(), "nothing was saved") {
		t.Fatalf("collision: %d %s", rec.Code, rec.Body.String())
	}
	if g, _ := e.tokens.ListGrants(ctx, mt.ID); len(g) != 2 || byID[a.ID] != "read/TMDB_API_KEY" {
		t.Fatalf("a refused save altered grants: %+v", g)
	}
	form = url.Values{"secret": {idStr(a.ID)}, "env_" + idStr(a.ID): {"lower"}}
	if rec := doForm(t, e.handler, path, form, cookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad env name: %d", rec.Code)
	}

	// Unticking everything removes everything; an unchanged save is not audited.
	if rec := doForm(t, e.handler, path, url.Values{}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("clear: %d", rec.Code)
	}
	if g, _ := e.tokens.ListGrants(ctx, mt.ID); len(g) != 0 {
		t.Fatalf("grants after clearing = %+v", g)
	}
	doForm(t, e.handler, path, url.Values{}, cookie)
	entries, err := e.audit.List(ctx, storage.AuditFilter{Action: audit.TokenGrantsSet, Limit: 10})
	if err != nil || len(entries) != 2 {
		t.Fatalf("audit entries = %d (%v), want 2 (the save and the clear; not the no-op)", len(entries), err)
	}
}

func TestWebGroupsPages(t *testing.T) {
	e := newEnv(t)
	completeSetupDirect(t, e)
	cookie := ownerSession(t, e)
	ctx := context.Background()
	a, _ := e.secrets.Create(ctx, "a", []byte("v"))
	b, _ := e.secrets.Create(ctx, "b", []byte("v"))
	_, mt, _ := e.tokens.Create(ctx, "svc", nil)
	if err := e.tokens.AddGrant(ctx, mt.ID, a.ID, "read", ""); err != nil {
		t.Fatal(err)
	}

	if rec := get(t, e, "/groups", nil); rec.Header().Get("Location") != "/login" {
		t.Fatalf("signed-out groups page: %d", rec.Code)
	}
	rec := doForm(t, e.handler, "/groups", url.Values{"name": {"arr"}}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	groups, _ := e.groups.List(ctx)
	if len(groups) != 1 {
		t.Fatalf("groups = %+v", groups)
	}
	gid := idStr(groups[0].ID)
	if rec := doForm(t, e.handler, "/groups", url.Values{"name": {"ARR"}}, cookie); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d", rec.Code)
	}
	if rec := doForm(t, e.handler, "/groups", url.Values{"name": {"  "}}, cookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("blank: %d", rec.Code)
	}

	if rec := doForm(t, e.handler, "/groups/"+gid+"/members", url.Values{"secret": {idStr(a.ID), idStr(b.ID)}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("members: %d", rec.Code)
	}
	if g, _ := e.groups.Get(ctx, groups[0].ID); len(g.SecretIDs) != 2 {
		t.Fatalf("members = %v", g.SecretIDs)
	}
	if rec := doForm(t, e.handler, "/groups/"+gid+"/members", url.Values{"secret": {"9999"}}, cookie); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown secret: %d", rec.Code)
	}
	if body := get(t, e, "/groups/"+gid, cookie).Body.String(); !strings.Contains(body, `value="`+idStr(a.ID)+`" checked`) {
		t.Fatalf("group page doesn't show members: %s", body)
	}
	if rec := doForm(t, e.handler, "/groups/"+gid+"/rename", url.Values{"name": {"media"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("rename: %d", rec.Code)
	}

	// Deleting a group touches no secret and no grant.
	if rec := doForm(t, e.handler, "/groups/"+gid+"/delete", url.Values{}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := get(t, e, "/groups/"+gid, cookie); rec.Code != http.StatusNotFound {
		t.Fatalf("deleted group page: %d", rec.Code)
	}
	if _, err := e.secrets.Get(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if g, _ := e.tokens.ListGrants(ctx, mt.ID); len(g) != 1 {
		t.Fatalf("deleting a group changed grants: %+v", g)
	}
}

func TestWebSecretPageAddsItToATokenOnlyOnce(t *testing.T) {
	e := newEnv(t)
	completeSetupDirect(t, e)
	cookie := ownerSession(t, e)
	ctx := context.Background()
	s, _ := e.secrets.Create(ctx, "db-password", []byte("v"))
	_, free, _ := e.tokens.Create(ctx, "free-one", nil)
	_, granted, _ := e.tokens.Create(ctx, "has-it", nil)
	_, revoked, _ := e.tokens.Create(ctx, "revoked-one", nil)
	if err := e.tokens.AddGrant(ctx, granted.ID, s.ID, "read", ""); err != nil {
		t.Fatal(err)
	}
	if err := e.tokens.Revoke(ctx, revoked.ID); err != nil {
		t.Fatal(err)
	}
	path := "/secrets/" + idStr(s.ID)

	page := get(t, e, path, cookie).Body.String()
	if !strings.Contains(page, "free-one") || strings.Contains(page, "has-it") || strings.Contains(page, "revoked-one") {
		t.Fatalf("dropdown should list only the free token:\n%s", page)
	}
	if !strings.Contains(page, `placeholder="DB_PASSWORD"`) {
		t.Fatalf("derived name not shown")
	}

	form := url.Values{"token_id": {idStr(free.ID)}, "permission": {"write"}, "env_name": {"DB_PASS"}}
	if rec := doForm(t, e.handler, path+"/grants", form, nil); rec.Header().Get("Location") != "/login" {
		t.Fatalf("signed-out add: %d", rec.Code)
	}
	if rec := doForm(t, e.handler, path+"/grants", form, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("add: %d %s", rec.Code, rec.Body.String())
	}
	grants, _ := e.tokens.ListGrants(ctx, free.ID)
	if len(grants) != 1 || grants[0].Permission != "write" || grants[0].EnvName != "DB_PASS" {
		t.Fatalf("grants = %+v", grants)
	}
	if page := get(t, e, path, cookie).Body.String(); strings.Contains(page, "free-one") || !strings.Contains(page, "already has this secret") {
		t.Fatalf("token should be gone from the dropdown after adding:\n%s", page)
	}

	// A bad name is refused and nothing is added.
	_, second, _ := e.tokens.Create(ctx, "second", nil)
	bad := url.Values{"token_id": {idStr(second.ID)}, "permission": {"read"}, "env_name": {"lower"}}
	if rec := doForm(t, e.handler, path+"/grants", bad, cookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad env name: %d", rec.Code)
	}
	if g, _ := e.tokens.ListGrants(ctx, second.ID); len(g) != 0 {
		t.Fatalf("a refused add created a grant: %+v", g)
	}
	entries, _ := e.audit.List(ctx, storage.AuditFilter{Action: audit.TokenGrant, Limit: 10})
	if len(entries) != 1 {
		t.Fatalf("grant audit entries = %d, want 1", len(entries))
	}
}
