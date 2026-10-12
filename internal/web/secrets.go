package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/envname"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// SecretsHandler serves the secrets pages. Values are never part of a
// page: the detail page fetches one only when "show" is clicked (see
// static/app.js), so only an actual reveal reaches the browser and the
// audit log.
type SecretsHandler struct {
	secrets *storage.SecretRepo
	tokens  *storage.TokenRepo
	groups  *storage.GroupRepo
	audit   audit.Logger
}

// NewSecretsHandler returns a SecretsHandler backed by the given repos.
func NewSecretsHandler(secrets *storage.SecretRepo, tokens *storage.TokenRepo, groups *storage.GroupRepo, auditLog audit.Logger) *SecretsHandler {
	return &SecretsHandler{secrets: secrets, tokens: tokens, groups: groups, audit: auditLog}
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
	// Created names the secret just saved by "save and add another".
	Created  string
	Groups   []model.SecretGroup
	Ticked   map[int64]bool
	NewGroup string
}

// ShowNew shows the new-secret form.
func (h *SecretsHandler) ShowNew(w http.ResponseWriter, r *http.Request) {
	h.renderNew(w, r, http.StatusOK, secretNewPage{})
}

func (h *SecretsHandler) renderNew(w http.ResponseWriter, r *http.Request, status int, page secretNewPage) {
	user, _ := session.FromContext(r.Context())
	groups, err := h.groups.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	page.User, page.Groups = &user, groups
	render(w, status, "secret_new", page)
}

// SubmitNew creates a secret and puts it in the ticked groups and in the
// new group, if one is named. "save" returns to the list; "save and add
// another" shows a blank form with the same groups ticked.
func (h *SecretsHandler) SubmitNew(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	ticked := map[int64]bool{}
	var groupIDs []int64
	for _, v := range r.Form["group"] {
		gid, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			http.Error(w, "invalid group id", http.StatusBadRequest)
			return
		}
		if !ticked[gid] {
			ticked[gid] = true
			groupIDs = append(groupIDs, gid)
		}
	}
	name, newGroup := r.FormValue("name"), strings.TrimSpace(r.FormValue("new_group"))
	created, err := h.secrets.Create(r.Context(), name, []byte(r.FormValue("value")))
	if err != nil {
		msg := "could not create the secret"
		if errors.Is(err, storage.ErrSecretNameTaken) {
			msg = "a secret with that name already exists"
		}
		h.renderNew(w, r, http.StatusBadRequest, secretNewPage{basePage: basePage{Error: msg}, Name: name, Ticked: ticked, NewGroup: newGroup})
		return
	}
	audit.Record(r.Context(), h.audit, audit.Event{
		Actor: audit.User(user.ID), Action: audit.SecretCreate, ResourceType: "secret", ResourceID: created.ID,
		Details: map[string]string{"name": created.Name},
	})

	if newGroup != "" {
		g, err := h.groups.Create(r.Context(), newGroup)
		switch {
		case err == nil:
			audit.Record(r.Context(), h.audit, audit.Event{
				Actor: audit.User(user.ID), Action: audit.GroupCreate, ResourceType: "group", ResourceID: g.ID,
				Details: map[string]string{"name": g.Name},
			})
		case errors.Is(err, storage.ErrGroupNameTaken):
			// Same name as an existing group: use that one.
			groups, lerr := h.groups.List(r.Context())
			if lerr != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			for _, eg := range groups {
				if strings.EqualFold(eg.Name, newGroup) {
					g = eg
				}
			}
		default:
			h.groupFailed(w, r, created.Name, ticked, newGroup, "group names are 1-64 characters, with no control characters")
			return
		}
		if !ticked[g.ID] {
			ticked[g.ID] = true
			groupIDs = append(groupIDs, g.ID)
		}
		newGroup = ""
	}

	for _, gid := range groupIDs {
		if err := h.groups.AddMember(r.Context(), gid, created.ID); err != nil {
			h.groupFailed(w, r, created.Name, ticked, newGroup, "a ticked group no longer exists")
			return
		}
		audit.Record(r.Context(), h.audit, audit.Event{
			Actor: audit.User(user.ID), Action: audit.GroupMembers, ResourceType: "group", ResourceID: gid,
			Details: map[string]string{"added_secret_id": strconv.FormatInt(created.ID, 10)},
		})
	}

	if r.FormValue("action") == "another" {
		h.renderNew(w, r, http.StatusOK, secretNewPage{Created: created.Name, Ticked: ticked})
		return
	}
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}

// groupFailed reports a group problem after the secret itself was saved:
// the secret is kept and the form comes back empty of it.
func (h *SecretsHandler) groupFailed(w http.ResponseWriter, r *http.Request, saved string, ticked map[int64]bool, newGroup, why string) {
	h.renderNew(w, r, http.StatusBadRequest, secretNewPage{
		basePage: basePage{Error: "secret " + saved + " was created, but not added to its groups: " + why + " - add it from the group page"},
		Ticked:   ticked, NewGroup: newGroup,
	})
}

type secretDetailPage struct {
	basePage
	Secret model.Secret
	// Tokens can still be given this secret (see TokenRepo.GrantableTo).
	Tokens []model.MachineToken
	// Derived is the environment variable name used when none is given.
	Derived string
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
	tokens, err := h.tokens.GrantableTo(r.Context(), s.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	render(w, status, "secret_detail", secretDetailPage{
		basePage: basePage{User: &user, Error: msg}, Secret: s, Tokens: tokens, Derived: envname.Derive(s.Name),
	})
}

// SubmitGrant gives one more token a grant on this secret.
func (h *SecretsHandler) SubmitGrant(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	s, ok := h.loadForm(w, r)
	if !ok {
		return
	}
	tokenID, err := parseFormInt64(r, "token_id")
	if err != nil {
		h.renderDetail(w, r, http.StatusBadRequest, "choose a token")
		return
	}
	permission, envName := r.FormValue("permission"), strings.TrimSpace(r.FormValue("env_name"))
	if permission != "read" && permission != "write" {
		http.Error(w, "invalid permission", http.StatusBadRequest)
		return
	}
	err = h.tokens.AddGrant(r.Context(), tokenID, s.ID, permission, envName)
	switch {
	case err == nil:
	case errors.Is(err, storage.ErrInvalidEnvName):
		h.renderDetail(w, r, http.StatusBadRequest, "invalid environment variable name: use uppercase letters, digits and underscores, not starting with a digit")
		return
	case errors.Is(err, storage.ErrEnvNameTaken):
		h.renderDetail(w, r, http.StatusConflict, "that token already uses this environment variable name for another secret - set a different one")
		return
	case errors.Is(err, storage.ErrNotFound), errors.Is(err, storage.ErrSecretNotFound):
		h.renderDetail(w, r, http.StatusNotFound, "that token no longer exists")
		return
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	audit.Record(r.Context(), h.audit, audit.Event{
		Actor: audit.User(user.ID), Action: audit.TokenGrant, ResourceType: "token", ResourceID: tokenID,
		Details: map[string]string{"secret_id": strconv.FormatInt(s.ID, 10), "permission": permission, "env_name": envName},
	})
	http.Redirect(w, r, "/secrets/"+strconv.FormatInt(s.ID, 10), http.StatusSeeOther)
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
