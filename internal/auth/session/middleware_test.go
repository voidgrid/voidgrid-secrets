package session_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

type fakeAuthenticator struct {
	wantToken string
	user      model.User
	err       error
}

func (f fakeAuthenticator) Authenticate(_ context.Context, plaintext string) (model.User, error) {
	if plaintext != f.wantToken {
		return model.User{}, session.ErrInvalidSession
	}
	return f.user, f.err
}

func TestMiddlewareRejectsMissingCookie(t *testing.T) {
	h := session.Middleware(fakeAuthenticator{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("expected next handler not to be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestMiddlewareRejectsInvalidSession(t *testing.T) {
	h := session.Middleware(fakeAuthenticator{wantToken: "vgs_sess_good"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { //nolint:gosec // fake test fixtures, not real credentials
		t.Fatal("expected next handler not to be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: "vgs_sess_wrong"}) //nolint:gosec // request cookie in a test; Secure/HttpOnly/SameSite are response-cookie attributes and don't apply here
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestMiddlewareAcceptsValidSessionAndPopulatesContext(t *testing.T) {
	wantUser := model.User{ID: 7, Username: "alice"}

	var gotUser model.User
	var gotOK bool

	h := session.Middleware(fakeAuthenticator{wantToken: "vgs_sess_good", user: wantUser})( //nolint:gosec // fake test fixture, not a real credential
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotUser, gotOK = session.FromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: "vgs_sess_good"}) //nolint:gosec // request cookie in a test; Secure/HttpOnly/SameSite are response-cookie attributes and don't apply here
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !gotOK || gotUser != wantUser {
		t.Fatalf("got user=%+v ok=%v, want %+v, true", gotUser, gotOK, wantUser)
	}
}

func TestMiddlewareReturns500OnInternalError(t *testing.T) {
	h := session.Middleware(fakeAuthenticator{wantToken: "vgs_sess_good", err: errors.New("db exploded")})( //nolint:gosec // fake test fixture, not a real credential
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("expected next handler not to be called")
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: "vgs_sess_good"}) //nolint:gosec // request cookie in a test; Secure/HttpOnly/SameSite are response-cookie attributes and don't apply here
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestSetCookieSetsSecureFlags(t *testing.T) {
	rec := httptest.NewRecorder()
	session.SetCookie(rec, "vgs_sess_abc", time.Now().Add(time.Hour))

	resp := rec.Result()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie missing required flags: %+v", c)
	}
}
