package token_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/token"
)

// FuzzMiddlewareAuthorizationHeader exercises the Authorization header
// parsing boundary: arbitrary header values (wrong scheme, missing/extra
// whitespace, binary garbage, huge strings) must never panic, only ever
// result in a 401 or (for a token the fake Authenticator accepts) 200.
func FuzzMiddlewareAuthorizationHeader(f *testing.F) {
	f.Add("")
	f.Add("Bearer ")
	f.Add("Bearer vgs_good")
	f.Add("bearer vgs_good")
	f.Add("Basic vgs_good")
	f.Add("Bearer\tvgs_good")
	f.Add("Bearer " + strings.Repeat("x", 4096))
	f.Add("Bearer \x00\x01\x02")
	f.Add("BearerBearerBearer")

	h := token.Middleware(fakeAuthenticator{wantToken: "vgs_good"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	f.Fuzz(func(t *testing.T, header string) {
		req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
		req.Header.Set("Authorization", header)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK && rec.Code != http.StatusUnauthorized {
			t.Fatalf("unexpected status %d for header %q", rec.Code, header)
		}
	})
}
