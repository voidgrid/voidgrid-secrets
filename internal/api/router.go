// Package api implements the voidgrid-secrets HTTP API using huma, which
// auto-generates an OpenAPI 3.1 spec and docs UI directly from the Go
// request/response types below — there is no separate, hand-maintained
// annotation layer to drift out of sync with behavior.
package api

import (
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/token"
	"github.com/voidgrid/voidgrid-secrets/internal/version"
)

// Deps collects everything NewRouter needs to wire up the API.
type Deps struct {
	SetupChecker   SetupStatusChecker
	TokenAuth      token.Authenticator
	SessionAuth    gosession.Authenticator
	SetupHandler   *SetupHandler
	AuthHandler    *AuthHandler
	SecretsHandler *SecretsHandler
	EnvHandler     *EnvHandler
	RecoverHandler *RecoverHandler
	TokensHandler  *TokensHandler
	GroupsHandler  *GroupsHandler
	AuditHandler   *AuditHandler
	// Audit records rejected machine tokens.
	Audit audit.Logger
}

// NewRouter builds the complete HTTP router: the OpenAPI spec and docs UI
// (served by huma at /openapi.json, /openapi.yaml, and /docs), and the
// /api/v1 route group.
//
// Every operation is gated by setupGateMiddleware: until the first-run
// setup wizard completes, only /setup/status and the setup-* operations
// are reachable. Once it completes, those setup-* operations become
// unreachable in turn, and everything else opens up.
//
// Within /api/v1 (voidgrid-secrets is single-user: the signed-in account
// can do everything; machine tokens only what they're granted):
//   - setup/*, auth/* (login, logout) and recover/* need no prior
//     authentication.
//   - secrets/* accepts a session cookie or a machine-token bearer header;
//     a token reaches only the secrets it's granted, and only the
//     read/update operations.
//   - env is machine-token-only: every secret the token may read, with the
//     environment variable name each is exposed under, for `run` and the
//     agent.
//   - tokens/*, groups/* and audit are session-only: a machine token can
//     never manage tokens, groups or read the audit log.
func NewRouter(deps Deps) http.Handler {
	router := chi.NewMux()
	router.Use(noStore)
	config := huma.DefaultConfig("voidgrid-secrets API", strings.TrimPrefix(version.Version, "v"))
	humaAPI := humachi.New(router, config)
	humaAPI.UseMiddleware(setupGateMiddleware(humaAPI, deps.SetupChecker))

	v1 := huma.NewGroup(humaAPI, "/api/v1")
	RegisterSetup(v1, deps.SetupHandler)
	RegisterAuth(v1, deps.AuthHandler)

	v1Secrets := huma.NewGroup(v1)
	v1Secrets.UseMiddleware(secretsAuthMiddleware(humaAPI, deps.TokenAuth, deps.SessionAuth, deps.Audit))
	RegisterSecrets(v1Secrets, deps.SecretsHandler)

	v1Env := huma.NewGroup(v1)
	v1Env.UseMiddleware(tokenAuthMiddleware(humaAPI, deps.TokenAuth, deps.Audit))
	RegisterEnv(v1Env, deps.EnvHandler)

	RegisterRecover(v1, deps.RecoverHandler)

	account := huma.NewGroup(v1)
	account.UseMiddleware(sessionAuthMiddleware(humaAPI, deps.SessionAuth))
	RegisterTokens(account, deps.TokensHandler)
	RegisterGroups(account, deps.GroupsHandler)
	RegisterAudit(account, deps.AuditHandler)

	// Same protection as the web UI (see web.crossOriginProtection): the
	// session-cookie routes would otherwise accept bodiless POSTs (token
	// revoke, logout) from a same-site page.
	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"title":"Forbidden","status":403,"detail":"cross-origin request refused"}`))
	}))
	return cop.Handler(router)
}

// noStore marks every API response uncacheable (responses carry secret
// values, fresh machine tokens, and recovery codes) and sets the
// hardening headers that apply to a JSON API. No CSP here: the /docs page
// huma serves loads its viewer from a CDN.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}
