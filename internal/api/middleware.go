package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/token"
)

// secretsAuthMiddleware authenticates a request via either a machine-token
// bearer header OR a human session cookie, trying the bearer header first.
// This is what makes /api/v1/secrets usable both by automated consumers
// (docker/.env use case) and by the web UI acting on a logged-in user's own
// secrets. Handlers distinguish which one authenticated them via
// token.FromContext / session.FromContext.
func secretsAuthMiddleware(api huma.API, tokenAuthr token.Authenticator, sessionAuthr gosession.Authenticator, auditLog audit.Logger) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if header := ctx.Header("Authorization"); strings.HasPrefix(header, "Bearer ") {
			if authed, ok := authenticateBearer(api, ctx, tokenAuthr, header, auditLog); ok {
				next(authed)
			}
			return
		}

		sessionToken := cookieValue(ctx, gosession.CookieName)
		if sessionToken == "" {
			_ = huma.WriteErr(api, ctx, 401, "authentication required (bearer token or session)")
			return
		}

		user, err := sessionAuthr.Authenticate(ctx.Context(), sessionToken)
		if err != nil {
			if errors.Is(err, gosession.ErrInvalidSession) {
				_ = huma.WriteErr(api, ctx, 401, "invalid or expired session")
				return
			}
			_ = huma.WriteErr(api, ctx, 500, "internal error")
			return
		}

		next(huma.WithContext(ctx, gosession.WithAuth(ctx.Context(), user)))
	}
}

// tokenAuthMiddleware requires a machine-token bearer header, with no
// session fallback. Used for /env, which exists only for automated
// consumers (`voidgrid-secrets run`), never for a logged-in human.
func tokenAuthMiddleware(api huma.API, tokenAuthr token.Authenticator, auditLog audit.Logger) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		header := ctx.Header("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			_ = huma.WriteErr(api, ctx, 401, "machine token required (Authorization: Bearer ...)")
			return
		}
		if authed, ok := authenticateBearer(api, ctx, tokenAuthr, header, auditLog); ok {
			next(authed)
		}
	}
}

// authenticateBearer validates a "Bearer <token>" header and returns the
// context carrying the machine token and its ACLs. On failure it has
// already written the error response and returns ok=false.
func authenticateBearer(api huma.API, ctx huma.Context, tokenAuthr token.Authenticator, header string, auditLog audit.Logger) (huma.Context, bool) {
	plaintext := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if plaintext == "" {
		_ = huma.WriteErr(api, ctx, 401, "missing bearer token")
		return nil, false
	}

	mt, acls, err := tokenAuthr.Authenticate(ctx.Context(), plaintext)
	if err != nil {
		if errors.Is(err, token.ErrInvalidToken) {
			audit.Record(ctx.Context(), auditLog, audit.Event{
				Actor: audit.Anonymous(), Action: audit.TokenAuthFailed, ResourceType: "token",
				Details: map[string]string{"path": ctx.URL().Path},
			})
			_ = huma.WriteErr(api, ctx, 401, "invalid or expired token")
			return nil, false
		}
		_ = huma.WriteErr(api, ctx, 500, "internal error")
		return nil, false
	}

	return huma.WithContext(ctx, token.WithAuth(ctx.Context(), mt, acls)), true
}

// sessionAuthMiddleware requires a valid session cookie, with no bearer
// fallback. Used for the admin routes, which must only ever be reachable
// by an authenticated human.
func sessionAuthMiddleware(api huma.API, sessionAuthr gosession.Authenticator) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		sessionToken := cookieValue(ctx, gosession.CookieName)
		if sessionToken == "" {
			_ = huma.WriteErr(api, ctx, 401, "missing session")
			return
		}

		user, err := sessionAuthr.Authenticate(ctx.Context(), sessionToken)
		if err != nil {
			if errors.Is(err, gosession.ErrInvalidSession) {
				_ = huma.WriteErr(api, ctx, 401, "invalid or expired session")
				return
			}
			_ = huma.WriteErr(api, ctx, 500, "internal error")
			return
		}

		next(huma.WithContext(ctx, gosession.WithAuth(ctx.Context(), user)))
	}
}

// cookieValue extracts a cookie's value from the request's raw Cookie
// header using net/http's standard parser, which correctly handles
// multiple cookies and escaping that naive string splitting would not.
func cookieValue(ctx huma.Context, name string) string {
	raw := ctx.Header("Cookie")
	if raw == "" {
		return ""
	}
	req := http.Request{Header: http.Header{"Cookie": []string{raw}}}
	c, err := req.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}
