package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNoStoreMarksResponsesUncacheable(t *testing.T) {
	h := noStore(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/setup/status", nil))

	want := map[string]string{
		"Cache-Control":          "no-store",
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "same-origin",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}
