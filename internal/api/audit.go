package api

import (
	"context"
	"strconv"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/token"
)

// actorFrom returns whoever authenticated this request: a machine token,
// a session user, or anonymous.
func actorFrom(ctx context.Context) audit.Actor {
	if mt, _, ok := token.FromContext(ctx); ok {
		return audit.Token(mt.ID)
	}
	if u, ok := gosession.FromContext(ctx); ok {
		return audit.User(u.ID)
	}
	return audit.Anonymous()
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
