package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
)

func ownerSession(t *testing.T, e env) *http.Cookie {
	t.Helper()
	tok, _, err := e.sessions.Create(context.Background(), 1, gosession.DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: gosession.CookieName, Value: tok} //nolint:gosec // request cookie in a test; Secure/HttpOnly/SameSite are response-cookie attributes and don't apply here
}

func get(t *testing.T, e env, path string, c *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

func TestWebAuditRecordsOnlyActualReveals(t *testing.T) {
	e := newEnv(t)
	completeSetupDirect(t, e)
	cookie := ownerSession(t, e)
	secret, err := e.secrets.Create(context.Background(), "viewer-secret", []byte("viewer-value"))
	if err != nil {
		t.Fatal(err)
	}
	id := strconv.FormatInt(secret.ID, 10)

	// Opening the page is not a reveal.
	get(t, e, "/secrets/"+id, cookie)
	if page := get(t, e, "/audit?action=reveal", cookie).Body.String(); strings.Contains(page, "viewer-secret") {
		t.Fatal("opening the secret's page was recorded as a reveal")
	}
	// Clicking show is.
	if rec := get(t, e, "/secrets/"+id+"/value", cookie); rec.Code != http.StatusOK {
		t.Fatalf("value: %d", rec.Code)
	}
	page := get(t, e, "/audit?action=reveal", cookie).Body.String()
	if !strings.Contains(page, "viewer-secret") || !strings.Contains(page, "via=web") {
		t.Fatalf("reveal not recorded: %s", page)
	}
	if strings.Contains(page, "viewer-value") {
		t.Fatal("audit page shows a secret value")
	}
	if rec := get(t, e, "/audit", nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("audit without a session: %d", rec.Code)
	}
}

func TestWebSecretRenameAndDelete(t *testing.T) {
	e := newEnv(t)
	completeSetupDirect(t, e)
	cookie := ownerSession(t, e)
	ctx := context.Background()
	secret, err := e.secrets.Create(ctx, "old-name", []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.secrets.Create(ctx, "taken", []byte("v")); err != nil {
		t.Fatal(err)
	}
	id := strconv.FormatInt(secret.ID, 10)

	if rec := doForm(t, e.handler, "/secrets/"+id+"/rename", url.Values{"name": {"taken"}}, cookie); rec.Code != http.StatusConflict {
		t.Fatalf("rename onto a taken name: %d", rec.Code)
	}
	if rec := doForm(t, e.handler, "/secrets/"+id+"/rename", url.Values{"name": {"new-name"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("rename: %d", rec.Code)
	}
	if got, _ := e.secrets.Get(ctx, secret.ID); got.Name != "new-name" {
		t.Fatalf("name = %q", got.Name)
	}
	if rec := doForm(t, e.handler, "/secrets/"+id+"/delete", url.Values{}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := get(t, e, "/secrets/"+id, cookie); rec.Code != http.StatusNotFound {
		t.Fatalf("after delete: %d", rec.Code)
	}
}
