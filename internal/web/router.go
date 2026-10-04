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
}

// NewRouter builds the web UI's router: the setup wizard (reachable only
// while setup is incomplete), login (reachable only once it is), and
// everything else behind a session (and, for /admin/*, an admin session).
func NewRouter(deps Deps) http.Handler {
	r := chi.NewMux()

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
			})
		})
	})

	return r
}
