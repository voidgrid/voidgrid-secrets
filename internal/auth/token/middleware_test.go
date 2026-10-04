package token_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/token"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

type fakeAuthenticator struct {
	wantToken string
	token     model.MachineToken
	acls      []model.TokenACL
	err       error
}

func (f fakeAuthenticator) Authenticate(_ context.Context, plaintext string) (model.MachineToken, []model.TokenACL, error) {
	if plaintext != f.wantToken {
		return model.MachineToken{}, nil, token.ErrInvalidToken
	}
	return f.token, f.acls, f.err
}

func TestMiddlewareRejectsMissingHeader(t *testing.T) {
	handlerCalled := false
	h := token.Middleware(fakeAuthenticator{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if handlerCalled {
		t.Fatal("expected next handler not to be called")
	}
}

func TestMiddlewareRejectsInvalidToken(t *testing.T) {
	h := token.Middleware(fakeAuthenticator{wantToken: "vgs_good"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("expected next handler not to be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.Header.Set("Authorization", "Bearer vgs_wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestMiddlewareAcceptsValidTokenAndPopulatesContext(t *testing.T) {
	wantMT := model.MachineToken{ID: 42, Description: "ci runner"}
	wantACLs := []model.TokenACL{{TokenID: 42, ResourceType: "secret", ResourceID: 1, Permission: "read"}}

	var gotMT model.MachineToken
	var gotACLs []model.TokenACL
	var gotOK bool

	h := token.Middleware(fakeAuthenticator{wantToken: "vgs_good", token: wantMT, acls: wantACLs})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotMT, gotACLs, gotOK = token.FromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.Header.Set("Authorization", "Bearer vgs_good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !gotOK {
		t.Fatal("expected FromContext to report ok=true")
	}
	if gotMT != wantMT {
		t.Fatalf("got token %+v, want %+v", gotMT, wantMT)
	}
	if len(gotACLs) != 1 || gotACLs[0] != wantACLs[0] {
		t.Fatalf("got ACLs %+v, want %+v", gotACLs, wantACLs)
	}
}

func TestMiddlewareReturns500OnInternalError(t *testing.T) {
	h := token.Middleware(fakeAuthenticator{wantToken: "vgs_good", err: errors.New("db exploded")})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("expected next handler not to be called")
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.Header.Set("Authorization", "Bearer vgs_good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}
