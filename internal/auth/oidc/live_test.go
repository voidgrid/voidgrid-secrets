//go:build live

package oidc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/oidc"
)

// TestLiveDiscoveryAndLoginRedirect runs against a real OIDC provider
// (configured in .env, see env.example; run via scripts/live-test.sh). It
// covers what can be automated without a browser: discovery against the
// real issuer, and that the sign-in redirect it produces carries this
// deployment's client ID, exact callback URL, PKCE challenge, and state.
// The interactive part - signing in at the provider - stays manual.
func TestLiveDiscoveryAndLoginRedirect(t *testing.T) {
	cfg := oidc.Config{
		Issuer:      requireEnv(t, "LIVE_OIDC_ISSUER"),
		ClientID:    requireEnv(t, "LIVE_OIDC_CLIENT_ID"),
		RedirectURI: requireEnv(t, "LIVE_OIDC_REDIRECT_URI"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := oidc.New(ctx, cfg)
	if err != nil {
		t.Fatalf("discovery against %s failed: %v", cfg.Issuer, err)
	}

	rec := httptest.NewRecorder()
	client.LoginHandler()(rec, httptest.NewRequest(http.MethodGet, "/login/oidc", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("login start status = %d, want %d", rec.Code, http.StatusFound)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Host == "" {
		t.Fatalf("login start redirect %q is not an absolute URL: %v", rec.Header().Get("Location"), err)
	}

	q := loc.Query()
	checks := map[string]string{
		"client_id":             cfg.ClientID,
		"redirect_uri":          cfg.RedirectURI,
		"response_type":         "code",
		"code_challenge_method": "S256",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Errorf("authorization request %s = %q, want %q", k, got, want)
		}
	}
	if q.Get("code_challenge") == "" || q.Get("state") == "" {
		t.Error("authorization request is missing its PKCE code_challenge or state")
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Errorf("authorization request scope %q does not include openid", q.Get("scope"))
	}
	if len(rec.Result().Cookies()) < 2 {
		t.Errorf("expected state and PKCE cookies to be set, got %d cookies", len(rec.Result().Cookies()))
	}
}

func requireEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" || v == "CHANGEME" {
		t.Fatalf("%s is not set - run live tests via scripts/live-test.sh", name)
	}
	return v
}
