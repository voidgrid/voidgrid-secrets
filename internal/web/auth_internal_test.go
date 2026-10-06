package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestContinueSignInRefreshesInsteadOfRedirecting(t *testing.T) {
	rec := httptest.NewRecorder()
	continueSignIn(rec)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 (a redirect would drop the SameSite=Strict session cookie)", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("got Location %q, want no redirect", loc)
	}
	if !strings.Contains(rec.Body.String(), `<meta http-equiv="refresh" content="0;url=/secrets">`) {
		t.Fatalf("expected a meta refresh to /secrets, body=%s", rec.Body.String())
	}
}

func TestRenderMarksPagesNoStore(t *testing.T) {
	rec := httptest.NewRecorder()
	render(rec, http.StatusOK, "login", loginPage{})

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("got Cache-Control %q, want no-store", got)
	}
}

func TestSecurityHeadersAreSet(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

	want := map[string]string{
		"Content-Security-Policy": webCSP,
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "same-origin",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

func TestCrossOriginProtectionRefusesSameSiteForms(t *testing.T) {
	h := crossOriginProtection(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name   string
		method string
		header map[string]string
		want   int
	}{
		// A sibling subdomain is the same *site*, so SameSite=Strict
		// still sends the cookie; this is what has to be refused.
		{"same-site POST", http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-site"}, http.StatusForbidden},
		{"cross-site POST", http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"other Origin, no Sec-Fetch-Site", http.MethodPost, map[string]string{"Origin": "https://other.example.com"}, http.StatusForbidden},
		{"same-origin POST", http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-origin"}, http.StatusOK},
		{"matching Origin", http.MethodPost, map[string]string{"Origin": "https://secrets.example.com"}, http.StatusOK},
		{"non-browser POST (no headers)", http.MethodPost, nil, http.StatusOK},
		{"cross-site GET", http.MethodGet, map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusOK},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, "https://secrets.example.com/admin/tokens/1/revoke", nil)
		for k, v := range c.header {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d", c.name, rec.Code, c.want)
		}
	}
}
