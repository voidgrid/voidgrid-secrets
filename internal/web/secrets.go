package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// SecretsHandler serves the secrets pages. Values are never part of a
// page: the detail page fetches one only when "show" is clicked (see
// static/app.js), so only an actual reveal reaches the browser and the
// audit log.
type SecretsHandler struct {
	secrets *storage.SecretRepo
	audit   audit.Logger
}

// NewSecretsHandler returns a SecretsHandler backed by the given repos.
func NewSecretsHandler(secrets *storage.SecretRepo, auditLog audit.Logger) *SecretsHandler {
	return &SecretsHandler{secrets: secrets, audit: auditLog}
}

type secretsListPage struct {
	basePage
	Secrets []model.Secret
}

// List shows every secret.
func (h *SecretsHandler) List(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	secrets, err := h.secrets.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	render(w, http.StatusOK, "secrets_list", secretsListPage{basePage: basePage{User: &user}, Secrets: secrets})
}

type secretNewPage struct {
	basePage
	Name string
}

// ShowNew shows the new-secret form.
func (h *SecretsHandler) ShowNew(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	render(w, http.StatusOK, "secret_new", secretNewPage{basePage: basePage{User: &user}})
}

// SubmitNew creates a secret.
func (h *SecretsHandler) SubmitNew(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	created, err := h.secrets.Create(r.Context(), name, []byte(r.FormValue("value")))
	if err != nil {
		msg := "could not create the secret"
		if errors.Is(err, storage.ErrSecretNameTaken) {
			msg = "a secret with that name already exists"
		}
		render(w, http.StatusBadRequest, "secret_new", secretNewPage{basePage: basePage{User: &user, Error: msg}, Name: name})
		return
	}
	audit.Record(r.Context(), h.audit, audit.Event{
		Actor: audit.User(user.ID), Action: audit.SecretCreate, ResourceType: "secret", ResourceID: created.ID,
		Details: map[string]string{"name": created.Name},
	})
	http.Redirect(w, r, "/secrets/"+strconv.FormatInt(created.ID, 10), http.StatusSeeOther)
}

type secretDetailPage struct {
	basePage
	Secret model.Secret
}

// Detail shows one secret, its value masked.
func (h *SecretsHandler) Detail(w http.ResponseWriter, r *http.Request) {
	h.renderDetail(w, r, http.StatusOK, "")
}

func (h *SecretsHandler) renderDetail(w http.ResponseWriter, r *http.Request, status int, msg string) {
	user, _ := session.FromContext(r.Context())
	s, ok := h.load(w, r)
	if !ok {
		return
	}
	render(w, status, "secret_detail", secretDetailPage{basePage: basePage{User: &user, Error: msg}, Secret: s})
}

// Value returns a secret's value as JSON, for the "show" button. It's
// recorded before it's sent.
func (h *SecretsHandler) Value(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	id, err := idParam(r)
	if err != nil {
		http.Error(w, "invalid secret id", http.StatusBadRequest)
		return
	}
	value, err := h.secrets.Reveal(r.Context(), id)
	if errors.Is(err, storage.ErrSecretNotFound) {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.audit.Log(r.Context(), audit.Event{
		Actor: audit.User(user.ID), Action: audit.SecretReveal, ResourceType: "secret", ResourceID: id,
		Details: map[string]string{"via": "web"},
	}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"value": string(value)})
}

// SubmitUpdate replaces a secret's value.
func (h *SecretsHandler) SubmitUpdate(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	s, ok := h.loadForm(w, r)
	if !ok {
		return
	}
	if _, err := h.secrets.Update(r.Context(), s.ID, []byte(r.FormValue("value"))); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	audit.Record(r.Context(), h.audit, audit.Event{Actor: audit.User(user.ID), Action: audit.SecretUpdate, ResourceType: "secret", ResourceID: s.ID})
	http.Redirect(w, r, "/secrets/"+strconv.FormatInt(s.ID, 10), http.StatusSeeOther)
}

// SubmitRename renames a secret.
func (h *SecretsHandler) SubmitRename(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	s, ok := h.loadForm(w, r)
	if !ok {
		return
	}
	renamed, err := h.secrets.Rename(r.Context(), s.ID, r.FormValue("name"))
	if errors.Is(err, storage.ErrSecretNameTaken) {
		h.renderDetail(w, r, http.StatusConflict, "a secret with that name already exists")
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	audit.Record(r.Context(), h.audit, audit.Event{
		Actor: audit.User(user.ID), Action: audit.SecretRename, ResourceType: "secret", ResourceID: s.ID,
		Details: map[string]string{"from": s.Name, "to": renamed.Name},
	})
	http.Redirect(w, r, "/secrets/"+strconv.FormatInt(s.ID, 10), http.StatusSeeOther)
}

// SubmitDelete deletes a secret and its token grants.
func (h *SecretsHandler) SubmitDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	s, ok := h.load(w, r)
	if !ok {
		return
	}
	if err := h.secrets.Delete(r.Context(), s.ID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	audit.Record(r.Context(), h.audit, audit.Event{
		Actor: audit.User(user.ID), Action: audit.SecretDelete, ResourceType: "secret", ResourceID: s.ID,
		Details: map[string]string{"name": s.Name},
	})
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}

// load fetches the secret named by the {id} URL parameter, writing an
// error response if it can't.
func (h *SecretsHandler) load(w http.ResponseWriter, r *http.Request) (model.Secret, bool) {
	id, err := idParam(r)
	if err != nil {
		http.Error(w, "invalid secret id", http.StatusBadRequest)
		return model.Secret{}, false
	}
	s, err := h.secrets.Get(r.Context(), id)
	if errors.Is(err, storage.ErrSecretNotFound) {
		http.Error(w, "secret not found", http.StatusNotFound)
		return model.Secret{}, false
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return model.Secret{}, false
	}
	return s, true
}

// loadForm is load plus parsing the form body.
func (h *SecretsHandler) loadForm(w http.ResponseWriter, r *http.Request) (model.Secret, bool) {
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return model.Secret{}, false
	}
	return h.load(w, r)
}
