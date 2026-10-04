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
