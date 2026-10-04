package session

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// CookieName is the name of the cookie carrying a session token.
const CookieName = "vgs_session"

// ErrInvalidSession is returned by an Authenticator when the presented
// session token doesn't exist, is revoked, expired, or belongs to a
// disabled user. Middleware maps it to 401; any other error is treated as
// an internal failure (500).
var ErrInvalidSession = errors.New("session: invalid, expired, or revoked")

// Authenticator validates a plaintext session token and returns the user
// it identifies.
type Authenticator interface {
	Authenticate(ctx context.Context, plaintext string) (model.User, error)
}

type contextKey int

const userContextKey contextKey = iota

// FromContext returns the authenticated user stashed by Middleware, if the
// request was authenticated via a session cookie.
func FromContext(ctx context.Context) (model.User, bool) {
	u, ok := ctx.Value(userContextKey).(model.User)
	return u, ok
}

// WithAuth returns a copy of ctx carrying the authenticated user,
// retrievable later via FromContext. Framework-specific middleware
// (net/http, huma, ...) should call this to stash results consistently.
func WithAuth(ctx context.Context, u model.User) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}

// Middleware returns HTTP middleware that requires a valid session cookie,
// authenticated via auth. Requests without a valid session are rejected
// with 401 before reaching next.
func Middleware(auth Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(CookieName)
			if err != nil || cookie.Value == "" {
				http.Error(w, "missing session", http.StatusUnauthorized)
				return
			}

			user, err := auth.Authenticate(r.Context(), cookie.Value)
			if err != nil {
				if errors.Is(err, ErrInvalidSession) {
					http.Error(w, "invalid or expired session", http.StatusUnauthorized)
					return
				}
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			next.ServeHTTP(w, r.WithContext(WithAuth(r.Context(), user)))
		})
	}
}

// SetCookie writes value as the session cookie on w, expiring at
// expiresAt. It always sets HttpOnly, Secure, and SameSite=Strict, per the
// project's security requirements for session cookies.
func SetCookie(w http.ResponseWriter, value string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearCookie removes the session cookie on logout.
func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}
