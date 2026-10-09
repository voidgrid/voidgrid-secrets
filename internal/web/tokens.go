package web

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
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
	audit   audit.Logger
}

// NewTokensHandler returns a TokensHandler backed by the given repos.
func NewTokensHandler(tokens *storage.TokenRepo, secrets *storage.SecretRepo, auditLog audit.Logger) *TokensHandler {
	return &TokensHandler{tokens: tokens, secrets: secrets, audit: auditLog}
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

// grantRow is one grant with its effective environment variable name.
type grantRow struct {
	model.TokenGrant
	EffectiveEnvName string
}

type tokenDetailPage struct {
	basePage
	Token   model.MachineToken
	Grants  []grantRow
	Secrets []model.Secret
}

// Detail shows a token, its grants, and the form to grant more.
func (h *TokensHandler) Detail(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		http.Error(w, "invalid token id", http.StatusBadRequest)
		return
	}
	h.renderDetail(w, r, id, http.StatusOK, "")
}

func (h *TokensHandler) renderDetail(w http.ResponseWriter, r *http.Request, id int64, status int, msg string) {
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
	page := tokenDetailPage{basePage: basePage{User: &user, Error: msg}, Token: mt, Secrets: secrets}
	for _, g := range grants {
		eff := g.EnvName
		if eff == "" {
			eff = envname.Derive(g.SecretName)
		}
		page.Grants = append(page.Grants, grantRow{TokenGrant: g, EffectiveEnvName: eff})
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

// SubmitUngrant removes a token's grant on one secret.
func (h *TokensHandler) SubmitUngrant(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	id, err := idParam(r)
	if err != nil {
		http.Error(w, "invalid token id", http.StatusBadRequest)
		return
	}
	secretID, err := strconv.ParseInt(chi.URLParam(r, "secretID"), 10, 64)
	if err != nil {
		http.Error(w, "invalid secret id", http.StatusBadRequest)
		return
	}
	switch err := h.tokens.RemoveGrant(r.Context(), id, secretID); {
	case err == nil:
	case errors.Is(err, storage.ErrNotFound):
		h.renderDetail(w, r, id, http.StatusNotFound, "that grant no longer exists")
		return
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	audit.Record(r.Context(), h.audit, audit.Event{
		Actor: audit.User(user.ID), Action: audit.TokenUngrant, ResourceType: "token", ResourceID: id,
		Details: map[string]string{"secret_id": strconv.FormatInt(secretID, 10)},
	})
	http.Redirect(w, r, "/tokens/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

// SubmitGrant grants a token read or write on a secret.
func (h *TokensHandler) SubmitGrant(w http.ResponseWriter, r *http.Request) {
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
	secretID, err := parseFormInt64(r, "secret_id")
	if err != nil {
		h.renderDetail(w, r, id, http.StatusBadRequest, "choose a secret")
		return
	}
	permission, envName := r.FormValue("permission"), r.FormValue("env_name")
	err = h.tokens.AddGrant(r.Context(), id, secretID, permission, envName)
	switch {
	case err == nil:
	case errors.Is(err, storage.ErrInvalidEnvName):
		h.renderDetail(w, r, id, http.StatusBadRequest, "invalid environment variable name: use uppercase letters, digits and underscores, not starting with a digit")
		return
	case errors.Is(err, storage.ErrEnvNameTaken):
		h.renderDetail(w, r, id, http.StatusConflict, "another secret on this token already uses that environment variable name - set a different one")
		return
	case errors.Is(err, storage.ErrSecretNotFound), errors.Is(err, storage.ErrNotFound):
		h.renderDetail(w, r, id, http.StatusNotFound, "that secret no longer exists")
		return
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	audit.Record(r.Context(), h.audit, audit.Event{
		Actor: audit.User(user.ID), Action: audit.TokenGrant, ResourceType: "token", ResourceID: id,
		Details: map[string]string{"secret_id": strconv.FormatInt(secretID, 10), "permission": permission, "env_name": envName},
	})
	http.Redirect(w, r, "/tokens/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}
