package api

import (
	"context"

	"github.com/danielgtaylor/huma/v2"

	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// AuditHandler serves the audit log to admins.
type AuditHandler struct {
	repo *storage.AuditRepo
}

// NewAuditHandler returns an AuditHandler backed by repo.
func NewAuditHandler(repo *storage.AuditRepo) *AuditHandler {
	return &AuditHandler{repo: repo}
}

// RegisterAudit registers the audit log operation on api (a session-only
// group).
func RegisterAudit(api huma.API, h *AuditHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "list-audit-log",
		Method:      "GET",
		Path:        "/audit",
		Summary:     "List audit log entries, newest first",
		Description: "Everything that reveals a value or changes something, plus failed and refused attempts. " +
			"Entries older than 14 days are pruned. Filter by action or token; page with before (the " +
			"next_before of the previous page).",
		Tags: []string{"audit"},
	}, h.List)
}

// ListAuditInput filters and pages the audit log.
type ListAuditInput struct {
	Action  string `query:"action" doc:"Only this action, e.g. reveal or login_failed"`
	TokenID int64  `query:"token_id" doc:"Only entries where this machine token acted or was acted on"`
	Before  int64  `query:"before" doc:"Only entries older than this id"`
	Limit   int    `query:"limit" minimum:"0" maximum:"500" doc:"Entries per page (default 100)"`
}

// ListAuditOutput is one page of entries.
type ListAuditOutput struct {
	Body struct {
		Entries []storage.AuditEntry `json:"entries"`
		// NextBefore is the before value for the next (older) page, or 0
		// if this page is the last.
		NextBefore int64 `json:"next_before"`
	}
}

// List returns one page of audit entries.
func (h *AuditHandler) List(ctx context.Context, in *ListAuditInput) (*ListAuditOutput, error) {
	limit := in.Limit
	if limit == 0 {
		limit = 100
	}
	entries, err := h.repo.List(ctx, storage.AuditFilter{Action: in.Action, TokenID: in.TokenID, BeforeID: in.Before, Limit: limit})
	if err != nil {
		return nil, huma.Error500InternalServerError("internal error")
	}
	out := &ListAuditOutput{}
	out.Body.Entries = entries
	if len(entries) == limit {
		out.Body.NextBefore = entries[len(entries)-1].ID
	}
	return out, nil
}
