package api

import (
	"context"
	"errors"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// TokensHandler implements machine-token management. It's session-only:
// a machine token can never manage tokens.
type TokensHandler struct {
	tokens *storage.TokenRepo
	audit  audit.Logger
}

// NewTokensHandler returns a TokensHandler backed by tokens.
func NewTokensHandler(tokens *storage.TokenRepo, auditLog audit.Logger) *TokensHandler {
	return &TokensHandler{tokens: tokens, audit: auditLog}
}

// RegisterTokens registers the token-management operations on api.
func RegisterTokens(api huma.API, h *TokensHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "list-tokens", Method: "GET", Path: "/tokens",
		Summary: "List machine tokens (never their values)", Tags: []string{"tokens"},
	}, h.List)
	huma.Register(api, huma.Operation{
		OperationID: "create-token", Method: "POST", Path: "/tokens",
		Summary: "Create a machine token; its value is returned exactly once", Tags: []string{"tokens"},
	}, h.Create)
	huma.Register(api, huma.Operation{
		OperationID: "get-token", Method: "GET", Path: "/tokens/{id}",
		Summary: "Get a machine token and the secrets it's granted", Tags: []string{"tokens"},
	}, h.Get)
	huma.Register(api, huma.Operation{
		OperationID: "revoke-token", Method: "POST", Path: "/tokens/{id}/revoke",
		Summary: "Revoke a machine token permanently", Tags: []string{"tokens"},
	}, h.Revoke)
	huma.Register(api, huma.Operation{
		OperationID: "grant-token", Method: "POST", Path: "/tokens/{id}/grants",
		Summary:     "Grant a machine token read or write on a secret",
		Description: "Granting the same secret again replaces the permission and environment variable name.",
		Tags:        []string{"tokens"},
	}, h.Grant)
}

// MachineTokenOut is a token's metadata as returned by the API.
type MachineTokenOut struct {
	ID          int64      `json:"id"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

func toMachineTokenOut(mt model.MachineToken) MachineTokenOut {
	return MachineTokenOut{
		ID: mt.ID, Description: mt.Description, CreatedAt: mt.CreatedAt,
		ExpiresAt: mt.ExpiresAt, RevokedAt: mt.RevokedAt, LastUsedAt: mt.LastUsedAt,
	}
}

// ListTokensOutput lists every token.
type ListTokensOutput struct {
	Body struct {
		Tokens []MachineTokenOut `json:"tokens"`
	}
}

// List returns every machine token, newest first.
func (h *TokensHandler) List(ctx context.Context, _ *EmptyInput) (*ListTokensOutput, error) {
	tokens, err := h.tokens.List(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	out := &ListTokensOutput{}
	out.Body.Tokens = []MachineTokenOut{}
	for _, mt := range tokens {
		out.Body.Tokens = append(out.Body.Tokens, toMachineTokenOut(mt))
	}
	return out, nil
}

// CreateTokenInput describes a new token.
type CreateTokenInput struct {
	Body struct {
		Description string     `json:"description"`
		ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	}
}

// CreateTokenOutput carries the new token's value, shown only here.
type CreateTokenOutput struct {
	Body struct {
		Token    string          `json:"token"`
		Metadata MachineTokenOut `json:"metadata"`
	}
}

// Create makes a new machine token.
func (h *TokensHandler) Create(ctx context.Context, in *CreateTokenInput) (*CreateTokenOutput, error) {
	plaintext, mt, err := h.tokens.Create(ctx, in.Body.Description, in.Body.ExpiresAt)
	if err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	details := map[string]string{"description": mt.Description}
	if mt.ExpiresAt != nil {
		details["expires_at"] = mt.ExpiresAt.UTC().Format(time.RFC3339)
	}
	audit.Record(ctx, h.audit, audit.Event{Actor: actorFrom(ctx), Action: audit.TokenCreate, ResourceType: "token", ResourceID: mt.ID, Details: details})
	out := &CreateTokenOutput{}
	out.Body.Token = plaintext
	out.Body.Metadata = toMachineTokenOut(mt)
	return out, nil
}

// TokenIDInput identifies a token.
type TokenIDInput struct {
	ID int64 `path:"id" doc:"Machine token ID"`
}

// GrantOut is one secret a token is granted.
type GrantOut struct {
	SecretID   int64  `json:"secret_id"`
	SecretName string `json:"secret_name"`
	Permission string `json:"permission"`
	// EnvName is the explicit environment variable name, or "" when it's
	// derived from the secret's name.
	EnvName string `json:"env_name,omitempty"`
}

// GetTokenOutput is a token with its grants.
type GetTokenOutput struct {
	Body struct {
		Token  MachineTokenOut `json:"token"`
		Grants []GrantOut      `json:"grants"`
	}
}

// Get returns a token and its grants.
func (h *TokensHandler) Get(ctx context.Context, in *TokenIDInput) (*GetTokenOutput, error) {
	mt, err := h.tokens.Get(ctx, in.ID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, huma.Error404NotFound("no such token")
	}
	if err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	grants, err := h.tokens.ListGrants(ctx, in.ID)
	if err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	out := &GetTokenOutput{}
	out.Body.Token = toMachineTokenOut(mt)
	out.Body.Grants = []GrantOut{}
	for _, g := range grants {
		out.Body.Grants = append(out.Body.Grants, GrantOut{SecretID: g.SecretID, SecretName: g.SecretName, Permission: g.Permission, EnvName: g.EnvName})
	}
	return out, nil
}

// Revoke revokes a token.
func (h *TokensHandler) Revoke(ctx context.Context, in *TokenIDInput) (*struct{}, error) {
	if err := h.tokens.Revoke(ctx, in.ID); err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	audit.Record(ctx, h.audit, audit.Event{Actor: actorFrom(ctx), Action: audit.TokenRevoke, ResourceType: "token", ResourceID: in.ID})
	return &struct{}{}, nil
}

// GrantInput gives a token a permission on a secret.
type GrantInput struct {
	ID   int64 `path:"id" doc:"Machine token ID"`
	Body struct {
		SecretID   int64  `json:"secret_id"`
		Permission string `json:"permission" enum:"read,write"`
		EnvName    string `json:"env_name,omitempty" doc:"The environment variable name 'voidgrid-secrets run' and the agent expose this secret under. Omit to derive it from the secret's name (db-password -> DB_PASSWORD)."`
	}
}

// Grant gives a token read or write on a secret.
func (h *TokensHandler) Grant(ctx context.Context, in *GrantInput) (*struct{}, error) {
	err := h.tokens.AddGrant(ctx, in.ID, in.Body.SecretID, in.Body.Permission, in.Body.EnvName)
	switch {
	case err == nil:
	case errors.Is(err, storage.ErrInvalidEnvName):
		return nil, huma.Error400BadRequest(err.Error())
	case errors.Is(err, storage.ErrEnvNameTaken):
		return nil, huma.Error409Conflict(err.Error())
	case errors.Is(err, storage.ErrSecretNotFound), errors.Is(err, storage.ErrNotFound):
		return nil, huma.Error404NotFound("no such token or secret")
	default:
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	audit.Record(ctx, h.audit, audit.Event{
		Actor: actorFrom(ctx), Action: audit.TokenGrant, ResourceType: "token", ResourceID: in.ID,
		Details: map[string]string{"secret_id": itoa(in.Body.SecretID), "permission": in.Body.Permission, "env_name": in.Body.EnvName},
	})
	return &struct{}{}, nil
}
