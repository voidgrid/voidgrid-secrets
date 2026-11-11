package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/recoverycode"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// An OIDC account whose provider is gone has no credentials to sign in
// with after a reset, so finishing the reset signs it in.
func TestOIDCRecoverySignsTheAccountIn(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u, err := e.users.SetupOIDC(ctx, "owner", "sub-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.authConfig.SaveOIDC(ctx, "https://idp.invalid", "id", "secret", "https://x/cb"); err != nil {
		t.Fatal(err)
	}
	if err := e.authConfig.CompleteOIDC(ctx); err != nil {
		t.Fatal(err)
	}
	codes, err := recoverycode.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.NewRecoveryCodeRepo(e.db).ReplaceForUser(ctx, u.ID, []string{crypto.HashToken(codes[0])}); err != nil {
		t.Fatal(err)
	}

	start := doForm(t, e.handler, "/recover", url.Values{"code": {codes[0]}}, nil)
	if start.Code != http.StatusSeeOther {
		t.Fatalf("start: status %d, body=%s", start.Code, start.Body.String())
	}
	var reset *http.Cookie
	for _, c := range start.Result().Cookies() {
		if c.Name == "vgs_reset" {
			reset = c
		}
	}
	if reset == nil {
		t.Fatal("no reset cookie")
	}

	done := doForm(t, e.handler, "/recover/reset", url.Values{}, reset)
	if done.Code != http.StatusOK {
		t.Fatalf("finish: status %d, body=%s", done.Code, done.Body.String())
	}
	session := extractSessionCookie(done)
	if session == nil {
		t.Fatal("finishing an OIDC reset set no session cookie")
	}
	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /secrets with the new session: status %d", rec.Code)
	}
}
