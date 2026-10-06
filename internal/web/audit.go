package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	oidcclient "github.com/voidgrid/voidgrid-secrets/internal/auth/oidc"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// currentActor is the logged-in user handling r.
func currentActor(r *http.Request) audit.Actor {
	if u, ok := session.FromContext(r.Context()); ok {
		return audit.User(u.ID)
	}
	return audit.Anonymous()
}

// auditedProvisioner records OIDC sign-ins refused for a disabled account,
// and accounts created on a first OIDC sign-in.
type auditedProvisioner struct {
	next  oidcclient.UserProvisioner
	audit audit.Logger
}

func (p auditedProvisioner) GetOrCreateUser(ctx context.Context, subject, preferredUsername string) (int64, bool, error) {
	id, created, err := p.next.GetOrCreateUser(ctx, subject, preferredUsername)
	switch {
	case errors.Is(err, model.ErrAccountDisabled):
		audit.Record(ctx, p.audit, audit.Event{
			Actor: audit.Anonymous(), Action: audit.LoginFailed, ResourceType: "user",
			Details: map[string]string{"method": "oidc", "subject": subject, "reason": "account disabled"},
		})
	case err == nil && created:
		audit.Record(ctx, p.audit, audit.Event{
			Actor: audit.User(id), Action: audit.UserCreate, ResourceType: "user", ResourceID: id,
			Details: map[string]string{"method": "oidc", "subject": subject, "username": preferredUsername},
		})
	}
	return id, created, err
}
