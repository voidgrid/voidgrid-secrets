package web

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/envname"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// TokensHandler serves the machine-token pages.
type TokensHandler struct {
	tokens  *storage.TokenRepo
	secrets *storage.SecretRepo
	groups  *storage.GroupRepo
	audit   audit.Logger
}

// NewTokensHandler returns a TokensHandler backed by the given repos.
func NewTokensHandler(tokens *storage.TokenRepo, secrets *storage.SecretRepo, groups *storage.GroupRepo, auditLog audit.Logger) *TokensHandler {
	return &TokensHandler{tokens: tokens, secrets: secrets, groups: groups, audit: auditLog}
}

type tokensPage struct {
	basePage
	Tokens []model.MachineToken
	// NewToken is a just-created token's value, shown once.
	NewToken string
	// NewTokenID links the just-created token to its page, where the
	// secrets it may read are granted.
	NewTokenID int64
}

// List shows every token.
func (h *TokensHandler) List(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	h.renderList(w, r, user, "", 0)
}

func (h *TokensHandler) renderList(w http.ResponseWriter, r *http.Request, user model.User, newToken string, newTokenID int64) {
	tokens, err := h.tokens.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	render(w, http.StatusOK, "tokens", tokensPage{basePage: basePage{User: &user}, Tokens: tokens, NewToken: newToken, NewTokenID: newTokenID})
}

// SubmitCreate creates a token and shows its value once.
func (h *TokensHandler) SubmitCreate(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	plaintext, mt, err := h.tokens.Create(r.Context(), r.FormValue("description"), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	audit.Record(r.Context(), h.audit, audit.Event{
		Actor: audit.User(user.ID), Action: audit.TokenCreate, ResourceType: "token", ResourceID: mt.ID,
		Details: map[string]string{"description": mt.Description},
	})
	h.renderList(w, r, user, plaintext, mt.ID)
}

// grantRow is one secret in the grant editor: whether the token has it,
// with what permission, and under which environment variable name.
type grantRow struct {
	SecretID   int64
	Name       string
	Checked    bool
	Permission string
	EnvName    string // explicit name, "" if derived
	Derived    string // the name used when EnvName is blank
}

// groupChoice is a quick-select toggle: ticking it ticks these secrets.
type groupChoice struct {
	Name    string
	Members string // comma-separated secret ids, for the page's script
	Count   int
}

type tokenDetailPage struct {
	basePage
	Token  model.MachineToken
	Rows   []grantRow
	Groups []groupChoice
}

// Detail shows a token and the editor for its grants.
func (h *TokensHandler) Detail(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		http.Error(w, "invalid token id", http.StatusBadRequest)
		return
	}
	h.renderDetail(w, r, id, http.StatusOK, "", nil)
}

// renderDetail renders the editor from the stored grants, or - after a
// refused save - from the submitted form, so nothing typed is lost.
func (h *TokensHandler) renderDetail(w http.ResponseWriter, r *http.Request, id int64, status int, msg string, submitted url.Values) {
	user, _ := session.FromContext(r.Context())
	mt, err := h.tokens.Get(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		http.Error(w, "token not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	grants, err := h.tokens.ListGrants(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	secrets, err := h.secrets.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	groups, err := h.groups.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	stored := map[int64]model.TokenGrant{}
	for _, g := range grants {
		stored[g.SecretID] = g
	}
	ticked := map[string]bool{}
	for _, v := range submitted["secret"] {
		ticked[v] = true
	}

	page := tokenDetailPage{basePage: basePage{User: &user, Error: msg}, Token: mt}
	for _, s := range secrets {
		key := strconv.FormatInt(s.ID, 10)
		row := grantRow{SecretID: s.ID, Name: s.Name, Permission: "read", Derived: envname.Derive(s.Name)}
		if submitted != nil {
			row.Checked = ticked[key]
			if p := submitted.Get("perm_" + key); p == "read" || p == "write" {
				row.Permission = p
			}
			row.EnvName = strings.TrimSpace(submitted.Get("env_" + key))
		} else if g, ok := stored[s.ID]; ok {
			row.Checked, row.Permission, row.EnvName = true, g.Permission, g.EnvName
		}
		page.Rows = append(page.Rows, row)
	}
	for _, g := range groups {
		ids := make([]string, len(g.SecretIDs))
		for i, sid := range g.SecretIDs {
			ids[i] = strconv.FormatInt(sid, 10)
		}
		page.Groups = append(page.Groups, groupChoice{Name: g.Name, Members: strings.Join(ids, ","), Count: len(ids)})
	}
	render(w, status, "token_detail", page)
}

// SubmitRevoke revokes a token.
func (h *TokensHandler) SubmitRevoke(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	id, err := idParam(r)
	if err != nil {
		http.Error(w, "invalid token id", http.StatusBadRequest)
		return
	}
	if err := h.tokens.Revoke(r.Context(), id); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	audit.Record(r.Context(), h.audit, audit.Event{Actor: audit.User(user.ID), Action: audit.TokenRevoke, ResourceType: "token", ResourceID: id})
	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

// SubmitGrants saves the editor: the ticked secrets become the token's
// complete set of grants, in one all-or-nothing change.
func (h *TokensHandler) SubmitGrants(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	id, err := idParam(r)
	if err != nil {
		http.Error(w, "invalid token id", http.StatusBadRequest)
		return
	}
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	var specs []storage.GrantSpec
	for _, v := range r.Form["secret"] {
		sid, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			http.Error(w, "invalid secret id", http.StatusBadRequest)
			return
		}
		perm := r.FormValue("perm_" + v)
		if perm == "" {
			perm = "read"
		}
		specs = append(specs, storage.GrantSpec{SecretID: sid, Permission: perm, EnvName: strings.TrimSpace(r.FormValue("env_" + v))})
	}

	change, err := h.tokens.SetGrants(r.Context(), id, specs)
	switch {
	case err == nil:
	case errors.Is(err, storage.ErrInvalidEnvName):
		h.renderDetail(w, r, id, http.StatusBadRequest, "invalid environment variable name: use uppercase letters, digits and underscores, not starting with a digit - nothing was saved", r.Form)
		return
	case errors.Is(err, storage.ErrEnvNameTaken):
		name := err.Error()
		if i := strings.LastIndex(name, ": "); i >= 0 {
			name = name[i+2:]
		}
		h.renderDetail(w, r, id, http.StatusConflict, "two secrets would use the environment variable name "+name+" - give one a different name; nothing was saved", r.Form)
		return
	case errors.Is(err, storage.ErrSecretNotFound):
		h.renderDetail(w, r, id, http.StatusNotFound, "a ticked secret no longer exists - nothing was saved", r.Form)
		return
	case errors.Is(err, storage.ErrNotFound):
		http.Error(w, "token not found", http.StatusNotFound)
		return
	case errors.Is(err, storage.ErrInvalidPermission):
		http.Error(w, "invalid permission", http.StatusBadRequest)
		return
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !change.Empty() {
		audit.Record(r.Context(), h.audit, audit.Event{
			Actor: audit.User(user.ID), Action: audit.TokenGrantsSet, ResourceType: "token", ResourceID: id,
			Details: change.AuditDetails(),
		})
	}
	http.Redirect(w, r, "/tokens/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}
