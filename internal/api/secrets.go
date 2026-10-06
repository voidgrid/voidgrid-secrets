package api

import (
	"context"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/token"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// SecretsHandler implements the /secrets operations, enforcing access for
// either an authenticated machine token (ACL-based) or an authenticated
// human session (ownership/group-membership/sharing-based) on every
// request.
type SecretsHandler struct {
	repo  *storage.SecretRepo
	audit audit.Logger
}

// NewSecretsHandler returns a SecretsHandler backed by repo.
func NewSecretsHandler(repo *storage.SecretRepo, auditLog audit.Logger) *SecretsHandler {
	return &SecretsHandler{repo: repo, audit: auditLog}
}

// SecretMetadata is the API representation of a secret's metadata, decoupled
// from the internal model.Secret type.
type SecretMetadata struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	OwnerType  string    `json:"owner_type"`
	OwnerID    int64     `json:"owner_id"`
	KeyVersion int       `json:"key_version"`
	CreatedBy  int64     `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func toSecretMetadata(s model.Secret) SecretMetadata {
	return SecretMetadata{
		ID:         s.ID,
		Name:       s.Name,
		OwnerType:  string(s.OwnerType),
		OwnerID:    s.OwnerID,
		KeyVersion: s.KeyVersion,
		CreatedBy:  s.CreatedBy,
		CreatedAt:  s.CreatedAt,
		UpdatedAt:  s.UpdatedAt,
	}
}

// GetSecretInput identifies a secret by its path ID.
type GetSecretInput struct {
	ID int64 `path:"id" doc:"Secret ID"`
}

// GetSecretMetadataOutput wraps a secret's metadata.
type GetSecretMetadataOutput struct {
	Body SecretMetadata
}

// RegisterSecrets registers the secrets operations on api (typically a
// huma.Group scoped to a path prefix and authenticated via
// secretsAuthMiddleware).
func RegisterSecrets(api huma.API, h *SecretsHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "get-secret-metadata",
		Method:      "GET",
		Path:        "/secrets/{id}/metadata",
		Summary:     "Get a secret's metadata (does not reveal its value)",
		Tags:        []string{"secrets"},
	}, h.GetMetadata)

	huma.Register(api, huma.Operation{
		OperationID: "reveal-secret",
		Method:      "GET",
		Path:        "/secrets/{id}",
		Summary:     "Reveal a secret's decrypted value",
		Tags:        []string{"secrets"},
	}, h.Reveal)

	huma.Register(api, huma.Operation{
		OperationID: "update-secret",
		Method:      "PUT",
		Path:        "/secrets/{id}",
		Summary:     "Rotate a secret's value in place",
		Tags:        []string{"secrets"},
	}, h.Update)
}

// GetMetadata returns a secret's metadata without decrypting its value.
func (h *SecretsHandler) GetMetadata(ctx context.Context, in *GetSecretInput) (*GetSecretMetadataOutput, error) {
	if err := h.requireAccess(ctx, in.ID, "read"); err != nil {
		return nil, err
	}

	s, err := h.repo.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("secret not found", err)
	}

	return &GetSecretMetadataOutput{Body: toSecretMetadata(s)}, nil
}

// RevealSecretOutput carries a secret's decrypted value.
type RevealSecretOutput struct {
	Body struct {
		Value string `json:"value" doc:"The secret's decrypted value"`
	}
}

// Reveal decrypts and returns a secret's value. Callers must hold "read"
// on the secret.
func (h *SecretsHandler) Reveal(ctx context.Context, in *GetSecretInput) (*RevealSecretOutput, error) {
	if err := h.requireAccess(ctx, in.ID, "read"); err != nil {
		return nil, err
	}

	value, err := h.repo.Reveal(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("secret not found", err)
	}
	// A value is never handed out unrecorded.
	if err := h.audit.Log(ctx, audit.Event{Actor: actorFrom(ctx), Action: audit.SecretReveal, ResourceType: "secret", ResourceID: in.ID}); err != nil {
		return nil, huma.Error500InternalServerError("internal error")
	}

	out := &RevealSecretOutput{}
	out.Body.Value = string(value)
	return out, nil
}

// UpdateSecretInput carries the new value for a secret rotation.
type UpdateSecretInput struct {
	ID   int64 `path:"id" doc:"Secret ID"`
	Body struct {
		Value string `json:"value" doc:"The secret's new value"`
	}
}

// Update rotates a secret's value in place, re-encrypting it under a fresh
// data-encryption key. Callers must hold "write" on the secret.
func (h *SecretsHandler) Update(ctx context.Context, in *UpdateSecretInput) (*GetSecretMetadataOutput, error) {
	if err := h.requireAccess(ctx, in.ID, "write"); err != nil {
		return nil, err
	}

	s, err := h.repo.Update(ctx, in.ID, []byte(in.Body.Value))
	if err != nil {
		return nil, huma.Error404NotFound("secret not found", err)
	}
	audit.Record(ctx, h.audit, audit.Event{Actor: actorFrom(ctx), Action: audit.SecretUpdate, ResourceType: "secret", ResourceID: in.ID})

	return &GetSecretMetadataOutput{Body: toSecretMetadata(s)}, nil
}

// requireAccess checks that whoever authenticated the request (see
// secretsAuthMiddleware) holds permission on the given secret: a machine
// token's ACLs, or a human session's ownership/group-membership/sharing
// access. Exactly one of the two contexts is ever populated, since the two
// authentication paths are mutually exclusive per request.
func (h *SecretsHandler) requireAccess(ctx context.Context, secretID int64, permission string) error {
	if _, acls, ok := token.FromContext(ctx); ok {
		if !token.CanAccess(acls, "secret", secretID, permission) {
			h.denied(ctx, secretID, permission)
			return huma.Error403Forbidden("token is not authorized for this secret")
		}
		return nil
	}

	if user, ok := gosession.FromContext(ctx); ok {
		allowed, err := h.repo.UserCanAccess(ctx, user.ID, secretID, permission)
		if err != nil {
			return huma.Error500InternalServerError("internal error", err)
		}
		if !allowed {
			h.denied(ctx, secretID, permission)
			return huma.Error403Forbidden("you are not authorized for this secret")
		}
		return nil
	}

	return huma.Error401Unauthorized("authentication required")
}

func (h *SecretsHandler) denied(ctx context.Context, secretID int64, permission string) {
	audit.Record(ctx, h.audit, audit.Event{
		Actor: actorFrom(ctx), Action: audit.AccessDenied, ResourceType: "secret", ResourceID: secretID,
		Details: map[string]string{"permission": permission},
	})
}
