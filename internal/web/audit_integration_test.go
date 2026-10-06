package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

func TestWebAuditViewerShowsEntriesToAdminsOnly(t *testing.T) {
	e := newEnv(t)
	completeSetupDirect(t, e)
	ctx := context.Background()

	admin, err := e.users.CreateWithPassword(ctx, "viewer-admin", "x")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.users.PromoteToAdmin(ctx, admin.ID); err != nil {
		t.Fatal(err)
	}
	plain, err := e.users.CreateWithPassword(ctx, "viewer-plain", "x")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := e.secrets.Create(ctx, model.OwnerUser, admin.ID, "viewer-secret", []byte("viewer-value"), admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	cookieFor := func(userID int64) *http.Cookie {
		tok, _, err := e.sessions.Create(ctx, userID, gosession.DefaultTTL)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: gosession.CookieName, Value: tok} //nolint:gosec // request cookie in a test; Secure/HttpOnly/SameSite are response-cookie attributes and don't apply here
	}
	get := func(path string, c *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		e.handler.ServeHTTP(rec, req)
		return rec
	}
	adminCookie := cookieFor(admin.ID)

	// Reveal through the UI, which records an entry.
	if rec := get("/secrets/"+strconv.FormatInt(secret.ID, 10)+"/reveal", adminCookie); rec.Code != http.StatusOK {
		t.Fatalf("reveal: %d", rec.Code)
	}

	rec := get("/admin/audit", adminCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin view: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"reveal", "viewer-secret", "user viewer-admin #"} {
		if !strings.Contains(body, want) {
			t.Errorf("audit page missing %q", want)
		}
	}
	if strings.Contains(body, "viewer-value") {
		t.Fatal("audit page shows a secret value")
	}

	filtered := get("/admin/audit?action=login_failed", adminCookie).Body.String()
	if strings.Contains(filtered, "viewer-secret") {
		t.Fatal("action filter ignored")
	}

	if rec := get("/admin/audit", cookieFor(plain.ID)); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin view: %d", rec.Code)
	}
}
