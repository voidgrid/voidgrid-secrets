package web

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// auditPageSize is how many entries one page of the viewer shows.
const auditPageSize = 100

// AuditHandler serves the audit log viewer.
type AuditHandler struct {
	repo   *storage.AuditRepo
	tokens *storage.TokenRepo
}

// NewAuditHandler returns an AuditHandler backed by the given repos.
func NewAuditHandler(repo *storage.AuditRepo, tokens *storage.TokenRepo) *AuditHandler {
	return &AuditHandler{repo: repo, tokens: tokens}
}

// auditRow is one entry, formatted for the table.
type auditRow struct {
	storage.AuditEntry
	Actor    string
	Resource string
}

type auditPage struct {
	basePage
	Rows    []auditRow
	Action  string
	TokenID int64
	// Tokens fill the token filter.
	Tokens []model.MachineToken
	// OlderURL links to the next (older) page with the same filters, or
	// is empty on the last page.
	OlderURL string
}

// List shows the newest audit entries matching the query's filters.
func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	q := r.URL.Query()
	tokenID, _ := strconv.ParseInt(q.Get("token_id"), 10, 64)
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)

	entries, err := h.repo.List(r.Context(), storage.AuditFilter{
		Action: q.Get("action"), TokenID: tokenID, BeforeID: before, Limit: auditPageSize,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	tokens, err := h.tokens.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	page := auditPage{basePage: basePage{User: &user}, Action: q.Get("action"), TokenID: tokenID, Tokens: tokens}
	for _, e := range entries {
		page.Rows = append(page.Rows, auditRow{
			AuditEntry: e,
			Actor:      describe(e.ActorType, e.ActorID, e.ActorName),
			Resource:   describe(e.ResourceType, e.ResourceID, e.ResourceName),
		})
	}
	if len(entries) == auditPageSize {
		older := url.Values{}
		if page.Action != "" {
			older.Set("action", page.Action)
		}
		if tokenID != 0 {
			older.Set("token_id", strconv.FormatInt(tokenID, 10))
		}
		older.Set("before", strconv.FormatInt(entries[len(entries)-1].ID, 10))
		page.OlderURL = "/audit?" + older.Encode()
	}
	render(w, http.StatusOK, "audit", page)
}

// describe formats an actor or resource as "type name #id", leaving out
// whatever doesn't apply.
func describe(kind string, id int64, name string) string {
	s := kind
	if name != "" {
		s += " " + name
	}
	if id != 0 {
		s += " #" + strconv.FormatInt(id, 10)
	}
	return s
}
