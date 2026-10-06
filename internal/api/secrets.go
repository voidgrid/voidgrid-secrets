package api

import (
	"context"
	"errors"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/token"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// SecretsHandler implements the secrets API. The signed-in account can do
// everything; a machine token can read (and, with a write grant, update
// the value of) only the secrets it's granted.
type SecretsHandler struct {
	repo  *storage.SecretRepo
	audit audit.Logger
}

// NewSecretsHandler returns a SecretsHandler backed by repo.
func NewSecretsHandler(repo *storage.SecretRepo, auditLog audit.Logger) *SecretsHandler {
	return &SecretsHandler{repo: repo, audit: auditLog}
}

// SecretMetadata is a secret without its value.
type SecretMetadata struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	KeyVersion int       `json:"key_version"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func toSecretMetadata(s model.Secret) SecretMetadata {
	return SecretMetadata{ID: s.ID, Name: s.Name, KeyVersion: s.KeyVersion, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt}
}

// RegisterSecrets registers the secrets operations on api (a group that
// accepts a session or a machine token).
func RegisterSecrets(api huma.API, h *SecretsHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "list-secrets", Method: "GET", Path: "/secrets",
		Summary: "List secrets (names and metadata, never values). Session only.", Tags: []string{"secrets"},
	}, h.List)
	huma.Register(api, huma.Operation{
		OperationID: "create-secret", Method: "POST", Path: "/secrets",
		Summary: "Create a secret. Session only.", Tags: []string{"secrets"},
	}, h.Create)
	huma.Register(api, huma.Operation{
		OperationID: "get-secret-metadata", Method: "GET", Path: "/secrets/{id}/metadata",
		Summary: "Get a secret's metadata (not its value)", Tags: []string{"secrets"},
	}, h.GetMetadata)
	huma.Register(api, huma.Operation{
		OperationID: "reveal-secret", Method: "GET", Path: "/secrets/{id}",
		Summary: "Reveal a secret's value (audited)", Tags: []string{"secrets"},
	}, h.Reveal)
	huma.Register(api, huma.Operation{
		OperationID: "update-secret", Method: "PUT", Path: "/secrets/{id}",
		Summary: "Replace a secret's value (a token needs a write grant)", Tags: []string{"secrets"},
	}, h.Update)
	huma.Register(api, huma.Operation{
		OperationID: "rename-secret", Method: "PUT", Path: "/secrets/{id}/name",
		Summary: "Rename a secret. Session only.", Tags: []string{"secrets"},
	}, h.Rename)
	huma.Register(api, huma.Operation{
		OperationID: "delete-secret", Method: "DELETE", Path: "/secrets/{id}",
		Summary: "Delete a secret and every token grant on it. Session only.", Tags: []string{"secrets"},
	}, h.Delete)
}

// ListSecretsOutput lists secrets.
type ListSecretsOutput struct {
	Body struct {
		Secrets []SecretMetadata `json:"secrets"`
	}
}

// List returns every secret's metadata.
func (h *SecretsHandler) List(ctx context.Context, _ *EmptyInput) (*ListSecretsOutput, error) {
	if err := requireSession(ctx); err != nil {
		return nil, err
	}
	secrets, err := h.repo.List(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	out := &ListSecretsOutput{}
	out.Body.Secrets = []SecretMetadata{}
	for _, s := range secrets {
		out.Body.Secrets = append(out.Body.Secrets, toSecretMetadata(s))
	}
	return out, nil
}

// CreateSecretInput is a new secret.
type CreateSecretInput struct {
	Body struct {
		Name  string `json:"name" minLength:"1"`
		Value string `json:"value"`
	}
}

// SecretOutput is one secret's metadata.
type SecretOutput struct {
	Body SecretMetadata
}

// Create stores a new secret.
func (h *SecretsHandler) Create(ctx context.Context, in *CreateSecretInput) (*SecretOutput, error) {
	if err := requireSession(ctx); err != nil {
		return nil, err
	}
	s, err := h.repo.Create(ctx, in.Body.Name, []byte(in.Body.Value))
	if errors.Is(err, storage.ErrSecretNameTaken) {
		return nil, huma.Error409Conflict("a secret with that name already exists")
	}
	if err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	audit.Record(ctx, h.audit, audit.Event{
		Actor: actorFrom(ctx), Action: audit.SecretCreate, ResourceType: "secret", ResourceID: s.ID,
		Details: map[string]string{"name": s.Name},
	})
	return &SecretOutput{Body: toSecretMetadata(s)}, nil
}

// SecretIDInput identifies a secret.
type SecretIDInput struct {
	ID int64 `path:"id" doc:"Secret ID"`
}

// GetMetadata returns a secret's metadata.
func (h *SecretsHandler) GetMetadata(ctx context.Context, in *SecretIDInput) (*SecretOutput, error) {
	if err := h.requireAccess(ctx, in.ID, "read"); err != nil {
		return nil, err
	}
	s, err := h.repo.Get(ctx, in.ID)
	if err != nil {
		return nil, notFoundOr500(err)
	}
	return &SecretOutput{Body: toSecretMetadata(s)}, nil
}

// RevealSecretOutput carries a secret's value.
type RevealSecretOutput struct {
	Body struct {
		Value string `json:"value" doc:"The secret's decrypted value"`
	}
}

// Reveal returns a secret's value, recording it first.
func (h *SecretsHandler) Reveal(ctx context.Context, in *SecretIDInput) (*RevealSecretOutput, error) {
	if err := h.requireAccess(ctx, in.ID, "read"); err != nil {
		return nil, err
	}
	value, err := h.repo.Reveal(ctx, in.ID)
	if err != nil {
		return nil, notFoundOr500(err)
	}
	// A value is never handed out unrecorded.
	if err := h.audit.Log(ctx, audit.Event{
		Actor: actorFrom(ctx), Action: audit.SecretReveal, ResourceType: "secret", ResourceID: in.ID,
		Details: map[string]string{"via": "api"},
	}); err != nil {
		return nil, huma.Error500InternalServerError("internal error")
	}
	out := &RevealSecretOutput{}
	out.Body.Value = string(value)
	return out, nil
}

// UpdateSecretInput replaces a secret's value.
type UpdateSecretInput struct {
	ID   int64 `path:"id" doc:"Secret ID"`
	Body struct {
		Value string `json:"value" doc:"The secret's new value"`
	}
}

// Update replaces a secret's value.
func (h *SecretsHandler) Update(ctx context.Context, in *UpdateSecretInput) (*SecretOutput, error) {
	if err := h.requireAccess(ctx, in.ID, "write"); err != nil {
		return nil, err
	}
	s, err := h.repo.Update(ctx, in.ID, []byte(in.Body.Value))
	if err != nil {
		return nil, notFoundOr500(err)
	}
	audit.Record(ctx, h.audit, audit.Event{Actor: actorFrom(ctx), Action: audit.SecretUpdate, ResourceType: "secret", ResourceID: in.ID})
	return &SecretOutput{Body: toSecretMetadata(s)}, nil
}

// RenameSecretInput renames a secret.
type RenameSecretInput struct {
	ID   int64 `path:"id" doc:"Secret ID"`
	Body struct {
		Name string `json:"name" minLength:"1"`
	}
}

// Rename changes a secret's name.
func (h *SecretsHandler) Rename(ctx context.Context, in *RenameSecretInput) (*SecretOutput, error) {
	if err := requireSession(ctx); err != nil {
		return nil, err
	}
	old, err := h.repo.Get(ctx, in.ID)
	if err != nil {
		return nil, notFoundOr500(err)
	}
	s, err := h.repo.Rename(ctx, in.ID, in.Body.Name)
	if errors.Is(err, storage.ErrSecretNameTaken) {
		return nil, huma.Error409Conflict("a secret with that name already exists")
	}
	if err != nil {
		return nil, notFoundOr500(err)
	}
	audit.Record(ctx, h.audit, audit.Event{
		Actor: actorFrom(ctx), Action: audit.SecretRename, ResourceType: "secret", ResourceID: in.ID,
		Details: map[string]string{"from": old.Name, "to": s.Name},
	})
	return &SecretOutput{Body: toSecretMetadata(s)}, nil
}

// Delete removes a secret and its token grants.
func (h *SecretsHandler) Delete(ctx context.Context, in *SecretIDInput) (*struct{}, error) {
	if err := requireSession(ctx); err != nil {
		return nil, err
	}
	old, err := h.repo.Get(ctx, in.ID)
	if err != nil {
		return nil, notFoundOr500(err)
	}
	if err := h.repo.Delete(ctx, in.ID); err != nil {
		return nil, notFoundOr500(err)
	}
	audit.Record(ctx, h.audit, audit.Event{
		Actor: actorFrom(ctx), Action: audit.SecretDelete, ResourceType: "secret", ResourceID: in.ID,
		Details: map[string]string{"name": old.Name},
	})
	return &struct{}{}, nil
}

// requireAccess allows the signed-in account everything, and a machine
// token only what its grants allow (recording a refusal).
func (h *SecretsHandler) requireAccess(ctx context.Context, secretID int64, permission string) error {
	if mt, grants, ok := token.FromContext(ctx); ok {
		if !token.CanAccess(grants, secretID, permission) {
			audit.Record(ctx, h.audit, audit.Event{
				Actor: audit.Token(mt.ID), Action: audit.AccessDenied, ResourceType: "secret", ResourceID: secretID,
				Details: map[string]string{"permission": permission},
			})
			return huma.Error403Forbidden("token is not granted this secret")
		}
		return nil
	}
	return requireSession(ctx)
}

// requireSession refuses requests authenticated by a machine token.
func requireSession(ctx context.Context) error {
	if _, ok := gosession.FromContext(ctx); ok {
		return nil
	}
	return huma.Error403Forbidden("only the signed-in account can do this, not a machine token")
}

func notFoundOr500(err error) error {
	if errors.Is(err, storage.ErrSecretNotFound) {
		return huma.Error404NotFound("secret not found")
	}
	return huma.Error500InternalServerError("internal error", err)
}
