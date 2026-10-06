package api

import (
	"context"
	"errors"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// SharesHandler implements secret-sharing management. Mounted under
// /api/v1/secrets, session-authenticated only (not reachable via machine
// token): sharing is a human decision about a secret the caller already
// has write access to, not something an automated consumer should do.
type SharesHandler struct {
	secrets *storage.SecretRepo
	shares  *storage.ShareRepo
	audit   audit.Logger
}

// NewSharesHandler returns a SharesHandler backed by secrets and shares.
func NewSharesHandler(secrets *storage.SecretRepo, shares *storage.ShareRepo, auditLog audit.Logger) *SharesHandler {
	return &SharesHandler{secrets: secrets, shares: shares, audit: auditLog}
}

// RegisterShares registers the sharing operations on api.
func RegisterShares(api huma.API, h *SharesHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "list-secret-shares",
		Method:      "GET",
		Path:        "/secrets/{id}/shares",
		Summary:     "List who a secret is shared with",
		Tags:        []string{"shares"},
	}, h.List)

	huma.Register(api, huma.Operation{
		OperationID: "create-secret-share",
		Method:      "POST",
		Path:        "/secrets/{id}/shares",
		Summary:     "Share a secret with another user or group",
		Tags:        []string{"shares"},
	}, h.Create)

	huma.Register(api, huma.Operation{
		OperationID: "delete-secret-share",
		Method:      "DELETE",
		Path:        "/secrets/{id}/shares/{granteeType}/{granteeId}",
		Summary:     "Revoke a secret share",
		Tags:        []string{"shares"},
	}, h.Delete)
}

// SecretShareOut is the API representation of a share.
type SecretShareOut struct {
	GranteeType string    `json:"grantee_type"`
	GranteeID   int64     `json:"grantee_id"`
	Permission  string    `json:"permission"`
	GrantedBy   int64     `json:"granted_by"`
	GrantedAt   time.Time `json:"granted_at"`
}

func toSecretShareOut(s model.SecretShare) SecretShareOut {
	return SecretShareOut{
		GranteeType: string(s.GranteeType),
		GranteeID:   s.GranteeID,
		Permission:  s.Permission,
		GrantedBy:   s.GrantedBy,
		GrantedAt:   s.GrantedAt,
	}
}

// ListSharesOutput wraps a secret's share list.
type ListSharesOutput struct {
	Body struct {
		Shares []SecretShareOut `json:"shares"`
	}
}

// List returns everyone a secret is explicitly shared with. Requires read
// access, same as viewing the secret itself.
func (h *SharesHandler) List(ctx context.Context, in *GetSecretInput) (*ListSharesOutput, error) {
	if err := h.requireSessionAccess(ctx, in.ID, "read"); err != nil {
		return nil, err
	}

	shares, err := h.shares.List(ctx, in.ID)
	if err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	out := &ListSharesOutput{}
	for _, s := range shares {
		out.Body.Shares = append(out.Body.Shares, toSecretShareOut(s))
	}
	return out, nil
}

// CreateShareInput carries the grantee and permission to share with.
type CreateShareInput struct {
	ID   int64 `path:"id" doc:"Secret ID"`
	Body struct {
		GranteeType string `json:"grantee_type" enum:"user,group"`
		GranteeID   int64  `json:"grantee_id"`
		Permission  string `json:"permission" enum:"read,write"`
	}
}

// CreateShareOutput is empty: success is signaled by a 2xx status.
type CreateShareOutput struct{}

// Create shares a secret with another user or group. Requires write
// access: sharing is a privileged action on the secret.
func (h *SharesHandler) Create(ctx context.Context, in *CreateShareInput) (*CreateShareOutput, error) {
	if err := h.requireSessionAccess(ctx, in.ID, "write"); err != nil {
		return nil, err
	}

	grantedBy, _ := gosession.FromContext(ctx) // presence already checked by requireSessionAccess
	if err := h.shares.Create(ctx, in.ID, model.OwnerType(in.Body.GranteeType), in.Body.GranteeID, in.Body.Permission, grantedBy.ID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, huma.Error404NotFound("no such " + in.Body.GranteeType)
		}
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	audit.Record(ctx, h.audit, audit.Event{
		Actor: actorFrom(ctx), Action: audit.ShareCreate, ResourceType: "secret", ResourceID: in.ID,
		Details: map[string]string{"grantee_type": in.Body.GranteeType, "grantee_id": itoa(in.Body.GranteeID), "permission": in.Body.Permission},
	})
	return &CreateShareOutput{}, nil
}

// DeleteShareInput identifies the share to revoke.
type DeleteShareInput struct {
	ID          int64  `path:"id" doc:"Secret ID"`
	GranteeType string `path:"granteeType" enum:"user,group"`
	GranteeID   int64  `path:"granteeId"`
}

// DeleteShareOutput is empty: success is signaled by a 2xx status.
type DeleteShareOutput struct{}

// Delete revokes a secret share. Requires write access.
func (h *SharesHandler) Delete(ctx context.Context, in *DeleteShareInput) (*DeleteShareOutput, error) {
	if err := h.requireSessionAccess(ctx, in.ID, "write"); err != nil {
		return nil, err
	}

	if err := h.shares.Delete(ctx, in.ID, model.OwnerType(in.GranteeType), in.GranteeID); err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	audit.Record(ctx, h.audit, audit.Event{
		Actor: actorFrom(ctx), Action: audit.ShareDelete, ResourceType: "secret", ResourceID: in.ID,
		Details: map[string]string{"grantee_type": in.GranteeType, "grantee_id": itoa(in.GranteeID)},
	})
	return &DeleteShareOutput{}, nil
}

// requireSessionAccess checks that the logged-in human (sharing is a
// session-only action; see RegisterShares) holds permission on the secret.
func (h *SharesHandler) requireSessionAccess(ctx context.Context, secretID int64, permission string) error {
	user, ok := gosession.FromContext(ctx)
	if !ok {
		return huma.Error401Unauthorized("authentication required")
	}
	allowed, err := h.secrets.UserCanAccess(ctx, user.ID, secretID, permission)
	if err != nil {
		return huma.Error500InternalServerError("internal error", err)
	}
	if !allowed {
		audit.Record(ctx, h.audit, audit.Event{
			Actor: audit.User(user.ID), Action: audit.AccessDenied, ResourceType: "secret", ResourceID: secretID,
			Details: map[string]string{"permission": permission, "operation": "sharing"},
		})
		return huma.Error403Forbidden("you are not authorized to manage sharing for this secret")
	}
	return nil
}
