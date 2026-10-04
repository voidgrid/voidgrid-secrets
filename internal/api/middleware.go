package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/token"
)

// secretsAuthMiddleware authenticates a request via either a machine-token
// bearer header OR a human session cookie, trying the bearer header first.
// This is what makes /api/v1/secrets usable both by automated consumers
// (docker/.env use case) and by the web UI acting on a logged-in user's own
// secrets. Handlers distinguish which one authenticated them via
// token.FromContext / session.FromContext.
func secretsAuthMiddleware(api huma.API, tokenAuthr token.Authenticator, sessionAuthr gosession.Authenticator) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if header := ctx.Header("Authorization"); strings.HasPrefix(header, "Bearer ") {
			plaintext := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
			if plaintext == "" {
				_ = huma.WriteErr(api, ctx, 401, "missing bearer token")
				return
			}

			mt, acls, err := tokenAuthr.Authenticate(ctx.Context(), plaintext)
			if err != nil {
				if errors.Is(err, token.ErrInvalidToken) {
					_ = huma.WriteErr(api, ctx, 401, "invalid or expired token")
					return
				}
				_ = huma.WriteErr(api, ctx, 500, "internal error")
				return
			}

			next(huma.WithContext(ctx, token.WithAuth(ctx.Context(), mt, acls)))
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

// adminOnlyMiddleware requires that sessionAuthMiddleware has already run
// and populated an admin user in context. It must be chained after
// sessionAuthMiddleware in the group's middleware list.
func adminOnlyMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		user, ok := gosession.FromContext(ctx.Context())
		if !ok || !user.IsAdmin {
			_ = huma.WriteErr(api, ctx, 403, "admin access required")
			return
		}
		next(ctx)
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
