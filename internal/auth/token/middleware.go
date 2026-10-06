package token

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// ErrInvalidToken is returned by an Authenticator when the presented token
// doesn't exist, is revoked, or has expired. Middleware maps it to 401;
// any other error is treated as an internal failure (500), so storage
// errors don't get mistaken for "bad credentials" by a caller probing the
// API.
var ErrInvalidToken = errors.New("token: invalid, expired, or revoked")

// Authenticator validates a plaintext bearer token and returns the machine
// token it identifies along with its resource ACLs.
type Authenticator interface {
	Authenticate(ctx context.Context, plaintext string) (model.MachineToken, []model.TokenGrant, error)
}

type contextKey int

const authInfoKey contextKey = iota

// authInfo is what Middleware stashes in the request context on success.
type authInfo struct {
	token model.MachineToken
	acls  []model.TokenGrant
}

// FromContext returns the authenticated machine token and its grants stashed
// by Middleware, if the request was authenticated via a machine token.
func FromContext(ctx context.Context) (model.MachineToken, []model.TokenGrant, bool) {
	info, ok := ctx.Value(authInfoKey).(authInfo)
	if !ok {
		return model.MachineToken{}, nil, false
	}
	return info.token, info.acls, true
}

// WithAuth returns a copy of ctx carrying the authenticated machine token
// and its grants, retrievable later via FromContext. Framework-specific
// middleware (net/http, huma, ...) that performs its own request
// extraction should call this to stash results consistently, so handlers
// can use FromContext regardless of which middleware authenticated them.
func WithAuth(ctx context.Context, mt model.MachineToken, acls []model.TokenGrant) context.Context {
	return context.WithValue(ctx, authInfoKey, authInfo{token: mt, acls: acls})
}

// Middleware returns HTTP middleware that requires a valid
// "Authorization: Bearer <token>" header, authenticated via auth. Requests
// without a valid token are rejected with 401 before reaching next.
//
// This is for machine-token-only routes (the automated docker/.env
// consumer API). Human session authentication (Phase 5) is handled by a
// separate middleware on separate routes, not layered with this one.
func Middleware(auth Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			plaintext, ok := bearerToken(r)
			if !ok {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}

			mt, acls, err := auth.Authenticate(r.Context(), plaintext)
			if err != nil {
				if errors.Is(err, ErrInvalidToken) {
					http.Error(w, "invalid or expired token", http.StatusUnauthorized)
					return
				}
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			ctx := WithAuth(r.Context(), mt, acls)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if tok == "" {
		return "", false
	}
	return tok, true
}
