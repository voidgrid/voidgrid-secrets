package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/conditional"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/token"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
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
			"derived from the secret's name. Every value returned is audited as a reveal by the token. " +
			"The response carries an ETag that changes whenever a granted secret's value or the set of " +
			"grants changes; send it back in If-None-Match to get 304 Not Modified (no values, nothing " +
			"audited) while nothing has changed.",
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

// GetEnvInput accepts If-None-Match, so a poller can skip unchanged
// responses.
type GetEnvInput struct {
	conditional.Params
}

// GetEnvOutput lists the token's secrets.
type GetEnvOutput struct {
	ETag string `header:"ETag"`
	Body struct {
		Secrets []EnvSecret `json:"secrets"`
	}
}

// Get returns every secret the authenticated machine token may read.
func (h *EnvHandler) Get(ctx context.Context, in *GetEnvInput) (*GetEnvOutput, error) {
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

	readable := grants[:0]
	for _, g := range grants {
		if token.CanAccess(acls, "secret", g.SecretID, "read") {
			readable = append(readable, g)
		}
	}

	// Decide on 304 before revealing anything, so an unchanged poll
	// decrypts nothing and writes no audit rows.
	etag := envETag(readable)
	if in.HasConditionalParams() {
		if err := in.PreconditionFailed(etag, time.Time{}); err != nil {
			return nil, huma.ErrorWithHeaders(err, http.Header{"ETag": {`"` + etag + `"`}})
		}
	}

	out := &GetEnvOutput{ETag: `"` + etag + `"`}
	out.Body.Secrets = []EnvSecret{}
	for _, g := range readable {
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

// envETag identifies the set of grants and the version of each granted
// value: it changes when a grant is added or removed, an env name changes,
// or a granted secret's value is updated. It's derived from metadata only,
// never from values.
func envETag(grants []model.EnvGrant) string {
	lines := make([]string, 0, len(grants))
	for _, g := range grants {
		lines = append(lines, fmt.Sprintf("%d|%s|%s", g.SecretID, g.EnvName, g.SecretUpdatedAt.UTC().Format(time.RFC3339Nano)))
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:16])
}
