package api

import (
	"context"
	"sort"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/token"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// EnvHandler serves GET /env: every secret the calling machine token may
// read, with the environment variable name each is exposed under. This is
// what `voidgrid-secrets run` fetches at process start.
type EnvHandler struct {
	tokens  *storage.TokenRepo
	secrets *storage.SecretRepo
	audit   *storage.AuditRepo
}

// NewEnvHandler returns an EnvHandler backed by the given repos.
func NewEnvHandler(tokens *storage.TokenRepo, secrets *storage.SecretRepo, audit *storage.AuditRepo) *EnvHandler {
	return &EnvHandler{tokens: tokens, secrets: secrets, audit: audit}
}

// RegisterEnv registers the env operation on api (a huma.Group
// authenticated via tokenAuthMiddleware).
func RegisterEnv(api huma.API, h *EnvHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "get-env",
		Method:      "GET",
		Path:        "/env",
		Summary:     "Fetch every secret this machine token may read, with its environment variable name",
		Description: "Machine tokens only. Returns the token's secret grants (read or write) with " +
			"decrypted values, each under the grant's environment variable name - explicit, or " +
			"derived from the secret's name. Every value returned is audited as a reveal by the token.",
		Tags: []string{"env"},
	}, h.Get)
}

// EnvSecret is one secret in a GET /env response.
type EnvSecret struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	EnvName string `json:"env_name"`
	Value   string `json:"value"`
}

// GetEnvOutput lists the token's secrets.
type GetEnvOutput struct {
	Body struct {
		Secrets []EnvSecret `json:"secrets"`
	}
}

// Get returns every secret the authenticated machine token may read.
func (h *EnvHandler) Get(ctx context.Context, _ *EmptyInput) (*GetEnvOutput, error) {
	mt, acls, ok := token.FromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("machine token required")
	}

	grants, err := h.tokens.EnvGrants(ctx, mt.ID)
	if err != nil {
		return nil, huma.Error500InternalServerError("internal error")
	}

	// AddACL already rejects collisions; this guards rows that predate it.
	seen := map[string]bool{}
	var dups []string
	for _, g := range grants {
		if seen[g.EnvName] {
			dups = append(dups, g.EnvName)
		}
		seen[g.EnvName] = true
	}
	if len(dups) > 0 {
		sort.Strings(dups)
		return nil, huma.Error409Conflict("more than one of this token's grants uses the environment variable name(s) " +
			strings.Join(dups, ", ") + " - give them distinct names")
	}

	out := &GetEnvOutput{}
	out.Body.Secrets = []EnvSecret{}
	for _, g := range grants {
		if !token.CanAccess(acls, "secret", g.SecretID, "read") {
			continue
		}
		value, err := h.secrets.Reveal(ctx, g.SecretID)
		if err != nil {
			return nil, huma.Error500InternalServerError("internal error")
		}
		if err := h.audit.Log(ctx, "token", mt.ID, "reveal", "secret", g.SecretID); err != nil {
			return nil, huma.Error500InternalServerError("internal error")
		}
		out.Body.Secrets = append(out.Body.Secrets, EnvSecret{
			ID:      g.SecretID,
			Name:    g.SecretName,
			EnvName: g.EnvName,
			Value:   string(value),
		})
	}
	return out, nil
}
