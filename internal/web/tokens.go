package web

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// TokensHandler implements the admin machine-token management pages.
type TokensHandler struct {
	tokens *storage.TokenRepo
}

// NewTokensHandler returns a TokensHandler backed by tokens.
func NewTokensHandler(tokens *storage.TokenRepo) *TokensHandler {
	return &TokensHandler{tokens: tokens}
}

type tokensPage struct {
	basePage
	Tokens   []model.MachineToken
	NewToken string
}

// List shows every machine token and the create-token form.
func (h *TokensHandler) List(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	tokens, err := h.tokens.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	render(w, http.StatusOK, "tokens", tokensPage{basePage: basePage{User: &user}, Tokens: tokens})
}

// SubmitCreate generates a new machine token and shows its plaintext once.
func (h *TokensHandler) SubmitCreate(w http.ResponseWriter, r *http.Request) {
	admin, _ := session.FromContext(r.Context())
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	var expiresAt *time.Time
	plaintext, _, err := h.tokens.Create(r.Context(), r.FormValue("description"), admin.ID, expiresAt)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	tokens, err := h.tokens.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	render(w, http.StatusOK, "tokens", tokensPage{basePage: basePage{User: &admin}, Tokens: tokens, NewToken: plaintext})
}

// SubmitRevoke revokes a machine token.
func (h *TokensHandler) SubmitRevoke(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		http.Error(w, "invalid token id", http.StatusBadRequest)
		return
	}
	if err := h.tokens.Revoke(r.Context(), id); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/tokens", http.StatusSeeOther)
}

type tokenDetailPage struct {
	basePage
	Token model.MachineToken
	// SecretGrants lists the token's secret grants with the effective
	// environment variable name each is exposed under.
	SecretGrants []model.EnvGrant
	// GroupGrants lists the token's group grants.
	GroupGrants []model.TokenACL
}

// Detail shows a token's grants and the grant-access form.
func (h *TokensHandler) Detail(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		http.Error(w, "invalid token id", http.StatusBadRequest)
		return
	}
	h.renderDetail(w, r, id, http.StatusOK, "")
}

// renderDetail renders a token's detail page, optionally with an error.
func (h *TokensHandler) renderDetail(w http.ResponseWriter, r *http.Request, id int64, status int, errMsg string) {
	user, _ := session.FromContext(r.Context())

	tokens, err := h.tokens.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var found *model.MachineToken
	for i := range tokens {
		if tokens[i].ID == id {
			found = &tokens[i]
			break
		}
	}
	if found == nil {
		http.Error(w, "token not found", http.StatusNotFound)
		return
	}

	secretGrants, err := h.tokens.EnvGrants(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	acls, err := h.tokens.ListACLs(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var groupGrants []model.TokenACL
	for _, a := range acls {
		if a.ResourceType == "group" {
			groupGrants = append(groupGrants, a)
		}
	}

	render(w, status, "token_detail", tokenDetailPage{
		basePage:     basePage{User: &user, Error: errMsg},
		Token:        *found,
		SecretGrants: secretGrants,
		GroupGrants:  groupGrants,
	})
}

// SubmitAddACL grants a machine token permission on a secret or group.
func (h *TokensHandler) SubmitAddACL(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		http.Error(w, "invalid token id", http.StatusBadRequest)
		return
	}
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	resourceID, err := parseFormInt64(r, "resource_id")
	if err != nil {
		h.renderDetail(w, r, id, http.StatusBadRequest, "invalid resource id")
		return
	}

	err = h.tokens.AddACL(r.Context(), id, r.FormValue("resource_type"), resourceID, r.FormValue("permission"), r.FormValue("env_name"))
	switch {
	case err == nil:
	case errors.Is(err, storage.ErrInvalidEnvName):
		h.renderDetail(w, r, id, http.StatusBadRequest, "invalid environment variable name: use uppercase letters, digits and underscores, not starting with a digit (env names apply to secret grants only)")
		return
	case errors.Is(err, storage.ErrEnvNameTaken):
		h.renderDetail(w, r, id, http.StatusConflict, "another secret on this token already uses that environment variable name - set a different one")
		return
	case errors.Is(err, storage.ErrSecretNotFound):
		h.renderDetail(w, r, id, http.StatusNotFound, "no secret with that id")
		return
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/tokens/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}
