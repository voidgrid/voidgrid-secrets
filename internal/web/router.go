package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	webassets "github.com/voidgrid/voidgrid-secrets/web"
)

// Deps collects everything NewRouter needs to wire up the web UI.
type Deps struct {
	SetupChecker setupChecker
	SessionAuth  session.Authenticator
	Setup        *SetupHandler
	Auth         *AuthHandler
	Secrets      *SecretsHandler
	Users        *UsersHandler
	Groups       *GroupsHandler
	Tokens       *TokensHandler
	Audit        *AuditHandler
}

// NewRouter builds the web UI's router: the setup wizard (reachable only
// while setup is incomplete), login (reachable only once it is), and
// everything else behind a session (and, for /admin/*, an admin session).
func NewRouter(deps Deps) http.Handler {
	r := chi.NewMux()
	r.Use(securityHeaders)

	r.Handle("/static/*", http.FileServerFS(webassets.FS))

	r.Group(func(r chi.Router) {
		r.Use(redirectIfSetupComplete(deps.SetupChecker))
		r.Get("/setup", deps.Setup.ShowInit)
		r.Post("/setup", deps.Setup.SubmitInit)
		r.Post("/setup/confirm", deps.Setup.SubmitConfirm)
		r.Get("/setup/oidc", deps.Setup.ShowOIDCSetup)
		r.Post("/setup/oidc", deps.Setup.SubmitOIDCSetup)
	})

	r.Group(func(r chi.Router) {
		r.Use(requireSetupComplete(deps.SetupChecker))
		r.Get("/login", deps.Auth.ShowLogin)
		r.Post("/login", deps.Auth.SubmitLogin)
		r.Post("/logout", deps.Auth.SubmitLogout)
		r.Get("/login/oidc", deps.Auth.StartOIDCLogin)
		r.Get("/login/oidc/callback", deps.Auth.OIDCCallback)
		r.Get("/login/recovery", deps.Auth.ShowRecoveryLogin)
		r.Post("/login/recovery", deps.Auth.SubmitRecoveryLogin)

		r.Group(func(r chi.Router) {
			r.Use(requireSession(deps.SessionAuth))

			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/secrets", http.StatusSeeOther)
			})

			r.Get("/secrets", deps.Secrets.List)
			r.Get("/secrets/new", deps.Secrets.ShowNew)
			r.Post("/secrets/new", deps.Secrets.SubmitNew)
			r.Get("/secrets/{id}", deps.Secrets.Detail)
			r.Post("/secrets/{id}/update", deps.Secrets.SubmitUpdate)
			r.Get("/secrets/{id}/reveal", deps.Secrets.Reveal)
			r.Post("/secrets/{id}/shares", deps.Secrets.SubmitCreateShare)
			r.Post("/secrets/{id}/shares/{granteeType}/{granteeId}/delete", deps.Secrets.SubmitDeleteShare)

			r.Group(func(r chi.Router) {
				r.Use(requireAdmin)

				r.Get("/admin/users", deps.Users.List)
				r.Post("/admin/users", deps.Users.SubmitCreate)
				r.Post("/admin/users/{id}/disabled", deps.Users.SubmitSetDisabled)

				r.Get("/admin/groups", deps.Groups.List)
				r.Post("/admin/groups", deps.Groups.SubmitCreate)
				r.Get("/admin/groups/{id}", deps.Groups.Detail)
				r.Post("/admin/groups/{id}/members", deps.Groups.SubmitAddMember)
				r.Post("/admin/groups/{id}/members/{userId}/delete", deps.Groups.SubmitRemoveMember)

				r.Get("/admin/tokens", deps.Tokens.List)
				r.Post("/admin/tokens", deps.Tokens.SubmitCreate)
				r.Get("/admin/tokens/{id}", deps.Tokens.Detail)
				r.Post("/admin/tokens/{id}/revoke", deps.Tokens.SubmitRevoke)
				r.Post("/admin/tokens/{id}/acls", deps.Tokens.SubmitAddACL)

				r.Get("/admin/audit", deps.Audit.List)
			})
		})
	})

	return crossOriginProtection(r)
}

// crossOriginProtection rejects state-changing requests (anything but
// GET/HEAD/OPTIONS) that a browser marks as coming from another origin,
// using Sec-Fetch-Site, falling back to comparing Origin with Host.
// SameSite=Strict on the session cookie isn't enough on its own: a sibling
// subdomain (other.example.com) is the same *site*, so its pages could
// otherwise submit forms with a logged-in admin's cookie. Requests with
// neither header (curl, `voidgrid-secrets run`) are not browser requests
// and pass through.
func crossOriginProtection(h http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
	}))
	return cop.Handler(h)
}

// webCSP allows only this origin's own assets. img-src also allows data:
// URIs for the server-rendered TOTP QR code; no template uses inline
// scripts or styles, so neither needs an exception.
const webCSP = "default-src 'self'; img-src 'self' data:; object-src 'none'; " +
	"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// securityHeaders sets the hardening headers every web UI response gets:
// no framing (clickjacking), no MIME sniffing, no cross-origin Referer
// (the OIDC callback URL carries the auth code in its query string).
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", webCSP)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}
