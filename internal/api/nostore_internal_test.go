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

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("got Cache-Control %q, want no-store", got)
	}
}
