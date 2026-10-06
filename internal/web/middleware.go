package web

import (
	"context"
	"net/http"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
)

// requireSession redirects to /login if there's no valid session cookie,
// otherwise populates the request context (via session.WithAuth) so
// downstream handlers and basePage.User both see the logged-in user.
func requireSession(authr session.Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(session.CookieName)
			if err != nil || cookie.Value == "" {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			user, err := authr.Authenticate(r.Context(), cookie.Value)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			next.ServeHTTP(w, r.WithContext(session.WithAuth(r.Context(), user)))
		})
	}
}

// setupChecker reports whether the first-run setup wizard has completed.
type setupChecker interface {
	IsComplete(ctx context.Context) (bool, error)
}

// requireSetupComplete redirects to /setup if the wizard hasn't run yet.
// Applied to every page except the wizard's own.
func requireSetupComplete(checker setupChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			complete, err := checker.IsComplete(r.Context())
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if !complete {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// redirectIfSetupComplete sends an already-set-up deployment away from the
// wizard pages to /login, so the wizard can never be re-run against a live
// deployment.
func redirectIfSetupComplete(checker setupChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			complete, err := checker.IsComplete(r.Context())
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if complete {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
