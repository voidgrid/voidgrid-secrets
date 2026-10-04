// Package api implements the voidgrid-secrets HTTP API using huma, which
// auto-generates an OpenAPI 3.1 spec and docs UI directly from the Go
// request/response types below — there is no separate, hand-maintained
// annotation layer to drift out of sync with behavior.
package api

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"

	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/token"
)

// Deps collects everything NewRouter needs to wire up the API.
type Deps struct {
	SetupChecker   SetupStatusChecker
	TokenAuth      token.Authenticator
	SessionAuth    gosession.Authenticator
	SetupHandler   *SetupHandler
	AuthHandler    *AuthHandler
	SecretsHandler *SecretsHandler
	SharesHandler  *SharesHandler
	UsersHandler   *UsersHandler
	GroupsHandler  *GroupsHandler
	TokensHandler  *TokensHandler
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
// Within /api/v1:
//   - setup/* and auth/* (login, logout) require no prior authentication.
//   - secrets/* accepts EITHER a machine-token bearer header OR a human
//     session cookie, authorizing via the token's ACLs or the session
//     user's ownership/group-membership/sharing access respectively.
//   - secrets/{id}/shares/* is session-only: sharing is a human decision,
//     not something a machine token should ever do.
//   - admin/* (users, groups, machine tokens) is session-only AND requires
//     the session user to be an admin. Machine tokens can never reach
//     these routes under any circumstance, by construction.
func NewRouter(deps Deps) http.Handler {
	router := chi.NewMux()
	router.Use(noStore)
	config := huma.DefaultConfig("voidgrid-secrets API", "0.1.0")
	humaAPI := humachi.New(router, config)
	humaAPI.UseMiddleware(setupGateMiddleware(humaAPI, deps.SetupChecker))

	v1 := huma.NewGroup(humaAPI, "/api/v1")
	RegisterSetup(v1, deps.SetupHandler)
	RegisterAuth(v1, deps.AuthHandler)

	v1Secrets := huma.NewGroup(v1)
	v1Secrets.UseMiddleware(secretsAuthMiddleware(humaAPI, deps.TokenAuth, deps.SessionAuth))
	RegisterSecrets(v1Secrets, deps.SecretsHandler)

	v1Shares := huma.NewGroup(v1)
	v1Shares.UseMiddleware(sessionAuthMiddleware(humaAPI, deps.SessionAuth))
	RegisterShares(v1Shares, deps.SharesHandler)

	admin := huma.NewGroup(v1)
	admin.UseMiddleware(sessionAuthMiddleware(humaAPI, deps.SessionAuth), adminOnlyMiddleware(humaAPI))
	RegisterUsers(admin, deps.UsersHandler)
	RegisterGroups(admin, deps.GroupsHandler)
	RegisterTokens(admin, deps.TokensHandler)

	return router
}

// noStore marks every API response uncacheable: responses carry secret
// values, fresh machine tokens, and recovery codes.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
