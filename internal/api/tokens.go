package api

import (
	"context"
	"time"

	"github.com/danielgtaylor/huma/v2"

	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// TokensHandler implements admin-only machine-token management. Mounted
// under /api/v1/admin: machine tokens must never be able to manage other
// tokens, so this is deliberately unreachable via bearer-token auth -
// session + admin only.
type TokensHandler struct {
	tokens *storage.TokenRepo
}

// NewTokensHandler returns a TokensHandler backed by tokens.
func NewTokensHandler(tokens *storage.TokenRepo) *TokensHandler {
	return &TokensHandler{tokens: tokens}
}

// RegisterTokens registers the admin token-management operations on api.
func RegisterTokens(api huma.API, h *TokensHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-list-tokens",
		Method:      "GET",
		Path:        "/admin/tokens",
		Summary:     "List all machine tokens (never their plaintext values)",
		Tags:        []string{"admin"},
	}, h.List)

	huma.Register(api, huma.Operation{
		OperationID: "admin-create-token",
		Method:      "POST",
		Path:        "/admin/tokens",
		Summary:     "Create a new machine token",
		Tags:        []string{"admin"},
	}, h.Create)

	huma.Register(api, huma.Operation{
		OperationID: "admin-revoke-token",
		Method:      "POST",
		Path:        "/admin/tokens/{id}/revoke",
		Summary:     "Revoke a machine token immediately",
		Tags:        []string{"admin"},
	}, h.Revoke)

	huma.Register(api, huma.Operation{
		OperationID: "admin-add-token-acl",
		Method:      "POST",
		Path:        "/admin/tokens/{id}/acls",
		Summary:     "Grant a machine token permission on a secret or group",
		Tags:        []string{"admin"},
	}, h.AddACL)
}

// MachineTokenOut is the API representation of a machine token's metadata
// (never its plaintext or hash).
type MachineTokenOut struct {
	ID          int64      `json:"id"`
	Description string     `json:"description"`
	CreatedBy   int64      `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

func toMachineTokenOut(mt model.MachineToken) MachineTokenOut {
	return MachineTokenOut{
		ID:          mt.ID,
		Description: mt.Description,
		CreatedBy:   mt.CreatedBy,
		CreatedAt:   mt.CreatedAt,
		ExpiresAt:   mt.ExpiresAt,
		RevokedAt:   mt.RevokedAt,
		LastUsedAt:  mt.LastUsedAt,
	}
}

// ListTokensOutput wraps the full token list.
type ListTokensOutput struct {
	Body struct {
		Tokens []MachineTokenOut `json:"tokens"`
	}
}

// List returns every machine token's metadata.
func (h *TokensHandler) List(ctx context.Context, _ *EmptyInput) (*ListTokensOutput, error) {
	tokens, err := h.tokens.List(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	out := &ListTokensOutput{}
	for _, mt := range tokens {
		out.Body.Tokens = append(out.Body.Tokens, toMachineTokenOut(mt))
	}
	return out, nil
}

// CreateTokenInput carries a new token's description and optional expiry.
type CreateTokenInput struct {
	Body struct {
		Description string     `json:"description"`
		ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	}
}

// CreateTokenOutput carries the new token's plaintext value, shown exactly
// once, and its metadata.
type CreateTokenOutput struct {
	Body struct {
		Token    string          `json:"token"`
		Metadata MachineTokenOut `json:"metadata"`
	}
}

// Create generates a new machine token, attributed to the calling admin.
func (h *TokensHandler) Create(ctx context.Context, in *CreateTokenInput) (*CreateTokenOutput, error) {
	admin, ok := gosession.FromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("authentication required")
	}

	plaintext, mt, err := h.tokens.Create(ctx, in.Body.Description, admin.ID, in.Body.ExpiresAt)
	if err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}

	out := &CreateTokenOutput{}
	out.Body.Token = plaintext
	out.Body.Metadata = toMachineTokenOut(mt)
	return out, nil
}

// TokenIDInput identifies a token by its path ID.
type TokenIDInput struct {
	ID int64 `path:"id" doc:"Machine token ID"`
}

// RevokeTokenOutput is empty: success is signaled by a 2xx status.
type RevokeTokenOutput struct{}

// Revoke invalidates a machine token immediately.
func (h *TokensHandler) Revoke(ctx context.Context, in *TokenIDInput) (*RevokeTokenOutput, error) {
	if err := h.tokens.Revoke(ctx, in.ID); err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	return &RevokeTokenOutput{}, nil
}

// AddTokenACLInput carries the resource and permission to grant.
type AddTokenACLInput struct {
	ID   int64 `path:"id" doc:"Machine token ID"`
	Body struct {
		ResourceType string `json:"resource_type" enum:"secret,group"`
		ResourceID   int64  `json:"resource_id"`
		Permission   string `json:"permission" enum:"read,write"`
	}
}

// AddTokenACLOutput is empty: success is signaled by a 2xx status.
type AddTokenACLOutput struct{}

// AddACL grants a machine token permission on a secret or group.
func (h *TokensHandler) AddACL(ctx context.Context, in *AddTokenACLInput) (*AddTokenACLOutput, error) {
	if err := h.tokens.AddACL(ctx, in.ID, in.Body.ResourceType, in.Body.ResourceID, in.Body.Permission); err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	return &AddTokenACLOutput{}, nil
}
