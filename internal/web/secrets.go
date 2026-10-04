package web

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// SecretsHandler implements the secrets browser, detail, reveal, and
// sharing pages, authorizing every action via the logged-in session user's
// access (see storage.SecretRepo.UserCanAccess) - the same access model
// used by the dual-auth API for session-authenticated requests.
type SecretsHandler struct {
	secrets *storage.SecretRepo
	shares  *storage.ShareRepo
	audit   *storage.AuditRepo
}

// NewSecretsHandler returns a SecretsHandler backed by the given repos.
func NewSecretsHandler(secrets *storage.SecretRepo, shares *storage.ShareRepo, audit *storage.AuditRepo) *SecretsHandler {
	return &SecretsHandler{secrets: secrets, shares: shares, audit: audit}
}

type secretsListPage struct {
	basePage
	Secrets []model.Secret
}

// List shows every secret the logged-in user can access.
func (h *SecretsHandler) List(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())

	secrets, err := h.secrets.ListForUser(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	render(w, http.StatusOK, "secrets_list", secretsListPage{
		basePage: basePage{User: &user},
		Secrets:  secrets,
	})
}

type secretNewPage struct {
	basePage
}

// ShowNew renders the new-secret form.
func (h *SecretsHandler) ShowNew(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	render(w, http.StatusOK, "secret_new", secretNewPage{basePage: basePage{User: &user}})
}

// SubmitNew creates a new secret owned by the logged-in user. Owning a
// secret as a group, rather than yourself, isn't exposed in the UI yet
// (deferred: it needs a group picker, and the API already supports it for
// anyone scripting against it directly).
func (h *SecretsHandler) SubmitNew(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	value := r.FormValue("value")

	created, err := h.secrets.Create(r.Context(), model.OwnerUser, user.ID, name, []byte(value), user.ID)
	if err != nil {
		render(w, http.StatusBadRequest, "secret_new", secretNewPage{basePage: basePage{User: &user, Error: err.Error()}})
		return
	}

	http.Redirect(w, r, "/secrets/"+strconv.FormatInt(created.ID, 10), http.StatusSeeOther)
}

type secretDetailPage struct {
	basePage
	Secret   model.Secret
	Shares   []model.SecretShare
	CanWrite bool
}

// Detail shows a secret's metadata, sharing, and (if the user holds write
// access) a rotate-value form.
func (h *SecretsHandler) Detail(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	id, err := secretIDParam(r)
	if err != nil {
		http.Error(w, "invalid secret id", http.StatusBadRequest)
		return
	}

	if !h.requireAccess(w, r, user.ID, id, "read") {
		return
	}

	s, err := h.secrets.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	}

	canWrite, err := h.secrets.UserCanAccess(r.Context(), user.ID, id, "write")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var shares []model.SecretShare
	if canWrite {
		shares, err = h.shares.List(r.Context(), id)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	render(w, http.StatusOK, "secret_detail", secretDetailPage{
		basePage: basePage{User: &user},
		Secret:   s,
		Shares:   shares,
		CanWrite: canWrite,
	})
}

// SubmitUpdate rotates a secret's value. Requires write access.
func (h *SecretsHandler) SubmitUpdate(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	id, err := secretIDParam(r)
	if err != nil {
		http.Error(w, "invalid secret id", http.StatusBadRequest)
		return
	}
	if !h.requireAccess(w, r, user.ID, id, "write") {
		return
	}
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	if _, err := h.secrets.Update(r.Context(), id, []byte(r.FormValue("value"))); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/secrets/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

type secretRevealPage struct {
	basePage
	Secret model.Secret
	Value  string
}

// Reveal decrypts and displays a secret's value. This is a deliberate,
// logged action: the value is never rendered on the list or detail pages.
func (h *SecretsHandler) Reveal(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	id, err := secretIDParam(r)
	if err != nil {
		http.Error(w, "invalid secret id", http.StatusBadRequest)
		return
	}
	if !h.requireAccess(w, r, user.ID, id, "read") {
		return
	}

	s, err := h.secrets.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	}
	value, err := h.secrets.Reveal(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := h.audit.Log(r.Context(), "user", user.ID, "reveal", "secret", id); err != nil {
		// Logging failure shouldn't block the reveal the user is authorized
		// for, but it's worth surfacing operationally.
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	render(w, http.StatusOK, "secret_reveal", secretRevealPage{
		basePage: basePage{User: &user},
		Secret:   s,
		Value:    string(value),
	})
}

// SubmitCreateShare grants another user or group access to a secret.
// Requires write access on the secret.
func (h *SecretsHandler) SubmitCreateShare(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	id, err := secretIDParam(r)
	if err != nil {
		http.Error(w, "invalid secret id", http.StatusBadRequest)
		return
	}
	if !h.requireAccess(w, r, user.ID, id, "write") {
		return
	}
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	granteeID, err := strconv.ParseInt(r.FormValue("grantee_id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid grantee id", http.StatusBadRequest)
		return
	}
	granteeType := model.OwnerType(r.FormValue("grantee_type"))
	permission := r.FormValue("permission")

	if err := h.shares.Create(r.Context(), id, granteeType, granteeID, permission, user.ID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/secrets/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

// SubmitDeleteShare revokes a secret share. Requires write access.
func (h *SecretsHandler) SubmitDeleteShare(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	id, err := secretIDParam(r)
	if err != nil {
		http.Error(w, "invalid secret id", http.StatusBadRequest)
		return
	}
	if !h.requireAccess(w, r, user.ID, id, "write") {
		return
	}

	granteeType := model.OwnerType(chi.URLParam(r, "granteeType"))
	granteeID, err := strconv.ParseInt(chi.URLParam(r, "granteeId"), 10, 64)
	if err != nil {
		http.Error(w, "invalid grantee id", http.StatusBadRequest)
		return
	}

	if err := h.shares.Delete(r.Context(), id, granteeType, granteeID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/secrets/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

// requireAccess checks userID's access to secretID, writing an appropriate
// error response (403 or 500) and returning false if access should be
// denied, or true if the caller should proceed.
func (h *SecretsHandler) requireAccess(w http.ResponseWriter, r *http.Request, userID, secretID int64, permission string) bool {
	allowed, err := h.secrets.UserCanAccess(r.Context(), userID, secretID, permission)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return false
	}
	if !allowed {
		http.Error(w, "you are not authorized for this secret", http.StatusForbidden)
		return false
	}
	return true
}

func secretIDParam(r *http.Request) (int64, error) {
	return idParam(r, "id")
}
