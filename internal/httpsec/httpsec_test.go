package httpsec

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func handler(t *testing.T, nets string) http.Handler {
	t.Helper()
	n, err := ParseNets(nets)
	if err != nil {
		t.Fatal(err)
	}
	return Middleware(n)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "vgs_session", Value: "v", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		w.WriteHeader(http.StatusNoContent)
	}))
}

func do(h http.Handler, path, remote string, mod func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.RemoteAddr = remote
	if mod != nil {
		mod(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAllowedPeerLosesSecure(t *testing.T) {
	h := handler(t, "192.168.1.0/24, 100.64.0.0/10, fd7a:115c:a1e0::/48")
	for _, remote := range []string{"192.168.1.20:5000", "100.101.2.3:1", "[fd7a:115c:a1e0::5]:9"} {
		c := do(h, "/login", remote, nil).Header().Get("Set-Cookie")
		if c == "" || strings.Contains(c, "Secure") || !strings.Contains(c, "HttpOnly") || !strings.Contains(c, "SameSite=Strict") {
			t.Errorf("%s: cookie = %q", remote, c)
		}
	}
}

func TestOtherPeerRefusedOnSignInOnly(t *testing.T) {
	h := handler(t, "192.168.1.0/24")
	for _, p := range []string{"/login", "/login/oidc", "/recover/reset", "/setup", "/setup/oidc/signin", "/api/v1/auth/login", "/api/v1/recover/complete", "/api/v1/setup/oidc"} {
		if rec := do(h, p, "8.8.8.8:1", nil); rec.Code != http.StatusForbidden {
			t.Errorf("%s: code %d, want 403", p, rec.Code)
		}
	}
	for _, p := range []string{"/api/v1/env", "/api/v1/secrets", "/api/v1/setup/status", "/loginx", "/static/app.js"} {
		if rec := do(h, p, "8.8.8.8:1", nil); rec.Code != http.StatusNoContent {
			t.Errorf("%s: code %d, want pass-through", p, rec.Code)
		}
	}
}

func TestEmptyListNeverDropsSecure(t *testing.T) {
	h := handler(t, "")
	if rec := do(h, "/login", "127.0.0.1:1", nil); rec.Code != http.StatusForbidden {
		t.Errorf("code %d, want 403", rec.Code)
	}
	if c := do(h, "/api/v1/env", "127.0.0.1:1", nil).Header().Get("Set-Cookie"); !strings.Contains(c, "Secure") {
		t.Errorf("cookie = %q", c)
	}
}

func TestHTTPSKeepsSecureEvenFromListedPeer(t *testing.T) {
	h := handler(t, "192.168.1.0/24")
	for name, mod := range map[string]func(*http.Request){
		"forwarded": func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https") },
		"tls":       func(r *http.Request) { r.TLS = &tls.ConnectionState{} },
	} {
		rec := do(h, "/login", "192.168.1.20:1", mod)
		if c := rec.Header().Get("Set-Cookie"); !strings.Contains(c, "Secure") {
			t.Errorf("%s: cookie = %q", name, c)
		}
		if rec := do(h, "/login", "8.8.8.8:1", mod); rec.Code != http.StatusNoContent {
			t.Errorf("%s: public peer over https got %d", name, rec.Code)
		}
	}
}

func TestForwardedForIsIgnored(t *testing.T) {
	h := handler(t, "192.168.1.0/24")
	rec := do(h, "/login", "8.8.8.8:1", func(r *http.Request) { r.Header.Set("X-Forwarded-For", "192.168.1.5") })
	if rec.Code != http.StatusForbidden {
		t.Errorf("code %d, want 403", rec.Code)
	}
}

func TestParseNetsRejectsBadInput(t *testing.T) {
	if _, err := ParseNets("192.168.1.0/24,nonsense"); err == nil {
		t.Error("want error")
	}
	if _, err := ParseNets("192.168.1.5"); err == nil {
		t.Error("bare IP should need a /prefix")
	}
}
