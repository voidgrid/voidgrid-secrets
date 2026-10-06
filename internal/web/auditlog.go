package web

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// auditPageSize is how many entries one page of the viewer shows.
const auditPageSize = 100

// AuditHandler serves the admin audit log viewer.
type AuditHandler struct {
	repo *storage.AuditRepo
}

// NewAuditHandler returns an AuditHandler backed by repo.
func NewAuditHandler(repo *storage.AuditRepo) *AuditHandler {
	return &AuditHandler{repo: repo}
}

// auditRow is one entry, formatted for the table.
type auditRow struct {
	storage.AuditEntry
	Actor    string
	Resource string
}

type auditPage struct {
	basePage
	Rows []auditRow
	// Filter holds the current filter values, to refill the form.
	Filter map[string]string
	// OlderURL links to the next (older) page with the same filters, or
	// is empty on the last page.
	OlderURL string
}

var auditFilterParams = []string{"action", "actor_type", "actor_id", "resource_type", "resource_id"}

// List shows the newest audit entries matching the query's filters.
func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	q := r.URL.Query()
	num := func(name string) int64 {
		n, _ := strconv.ParseInt(q.Get(name), 10, 64)
		return n
	}

	entries, err := h.repo.List(r.Context(), storage.AuditFilter{
		Action:       q.Get("action"),
		ActorType:    q.Get("actor_type"),
		ActorID:      num("actor_id"),
		ResourceType: q.Get("resource_type"),
		ResourceID:   num("resource_id"),
		BeforeID:     num("before"),
		Limit:        auditPageSize,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	page := auditPage{basePage: basePage{User: &user}, Filter: map[string]string{}}
	older := url.Values{}
	for _, name := range auditFilterParams {
		if v := q.Get(name); v != "" {
			page.Filter[name] = v
			older.Set(name, v)
		}
	}
	for _, e := range entries {
		page.Rows = append(page.Rows, auditRow{
			AuditEntry: e,
			Actor:      describe(e.ActorType, e.ActorID, e.ActorName),
			Resource:   describe(e.ResourceType, e.ResourceID, e.ResourceName),
		})
	}
	if len(entries) == auditPageSize {
		older.Set("before", strconv.FormatInt(entries[len(entries)-1].ID, 10))
		page.OlderURL = "/admin/audit?" + older.Encode()
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
