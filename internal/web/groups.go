package web

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// GroupsHandler serves the groups pages. Groups are a UI convenience:
// named sets of secrets to tick together on the token editor. Grants and
// the API know nothing about them.
type GroupsHandler struct {
	groups  *storage.GroupRepo
	secrets *storage.SecretRepo
	audit   audit.Logger
}

// NewGroupsHandler returns a GroupsHandler backed by the given repos.
func NewGroupsHandler(groups *storage.GroupRepo, secrets *storage.SecretRepo, auditLog audit.Logger) *GroupsHandler {
	return &GroupsHandler{groups: groups, secrets: secrets, audit: auditLog}
}

type groupsPage struct {
	basePage
	Groups []model.SecretGroup
	// Name refills the create form after a refused submit.
	Name string
}

// List shows every group and the form to create one.
func (h *GroupsHandler) List(w http.ResponseWriter, r *http.Request) {
	h.renderList(w, r, http.StatusOK, "", "")
}

func (h *GroupsHandler) renderList(w http.ResponseWriter, r *http.Request, status int, msg, name string) {
	user, _ := session.FromContext(r.Context())
	groups, err := h.groups.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	render(w, status, "groups", groupsPage{basePage: basePage{User: &user, Error: msg}, Groups: groups, Name: name})
}

// SubmitCreate creates an empty group and opens it.
func (h *GroupsHandler) SubmitCreate(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	g, err := h.groups.Create(r.Context(), name)
	switch {
	case err == nil:
	case errors.Is(err, storage.ErrGroupNameTaken):
		h.renderList(w, r, http.StatusConflict, "a group with that name already exists", name)
		return
	case errors.Is(err, storage.ErrInvalidGroupName):
		h.renderList(w, r, http.StatusBadRequest, "group names are 1-64 characters, with no control characters", name)
		return
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	audit.Record(r.Context(), h.audit, audit.Event{
		Actor: audit.User(user.ID), Action: audit.GroupCreate, ResourceType: "group", ResourceID: g.ID,
		Details: map[string]string{"name": g.Name},
	})
	http.Redirect(w, r, "/groups/"+strconv.FormatInt(g.ID, 10), http.StatusSeeOther)
}

type memberRow struct {
	SecretID int64
	Name     string
	Checked  bool
}

type groupDetailPage struct {
	basePage
	Group model.SecretGroup
	Rows  []memberRow
}

// Detail shows a group with a checklist of every secret.
func (h *GroupsHandler) Detail(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		http.Error(w, "invalid group id", http.StatusBadRequest)
		return
	}
	h.renderDetail(w, r, id, http.StatusOK, "")
}

func (h *GroupsHandler) renderDetail(w http.ResponseWriter, r *http.Request, id int64, status int, msg string) {
	user, _ := session.FromContext(r.Context())
	g, err := h.groups.Get(r.Context(), id)
	if errors.Is(err, storage.ErrGroupNotFound) {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	secrets, err := h.secrets.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	member := map[int64]bool{}
	for _, sid := range g.SecretIDs {
		member[sid] = true
	}
	page := groupDetailPage{basePage: basePage{User: &user, Error: msg}, Group: g}
	for _, s := range secrets {
		page.Rows = append(page.Rows, memberRow{SecretID: s.ID, Name: s.Name, Checked: member[s.ID]})
	}
	render(w, status, "group_detail", page)
}

// SubmitMembers saves the checklist as the group's complete membership.
func (h *GroupsHandler) SubmitMembers(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	id, err := idParam(r)
	if err != nil {
		http.Error(w, "invalid group id", http.StatusBadRequest)
		return
	}
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	var ids []int64
	for _, v := range r.Form["secret"] {
		sid, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			http.Error(w, "invalid secret id", http.StatusBadRequest)
			return
		}
		ids = append(ids, sid)
	}
	switch err := h.groups.SetMembers(r.Context(), id, ids); {
	case err == nil:
	case errors.Is(err, storage.ErrGroupNotFound):
		http.Error(w, "group not found", http.StatusNotFound)
		return
	case errors.Is(err, storage.ErrSecretNotFound):
		h.renderDetail(w, r, id, http.StatusNotFound, "a ticked secret no longer exists - nothing was saved")
		return
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	audit.Record(r.Context(), h.audit, audit.Event{
		Actor: audit.User(user.ID), Action: audit.GroupMembers, ResourceType: "group", ResourceID: id,
		Details: map[string]string{"count": strconv.Itoa(len(ids))},
	})
	http.Redirect(w, r, "/groups/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

// SubmitRename renames a group.
func (h *GroupsHandler) SubmitRename(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	id, err := idParam(r)
	if err != nil {
		http.Error(w, "invalid group id", http.StatusBadRequest)
		return
	}
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	old, err := h.groups.Get(r.Context(), id)
	if errors.Is(err, storage.ErrGroupNotFound) {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	name := r.FormValue("name")
	switch err := h.groups.Rename(r.Context(), id, name); {
	case err == nil:
	case errors.Is(err, storage.ErrGroupNameTaken):
		h.renderDetail(w, r, id, http.StatusConflict, "a group with that name already exists")
		return
	case errors.Is(err, storage.ErrInvalidGroupName):
		h.renderDetail(w, r, id, http.StatusBadRequest, "group names are 1-64 characters, with no control characters")
		return
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	audit.Record(r.Context(), h.audit, audit.Event{
		Actor: audit.User(user.ID), Action: audit.GroupRename, ResourceType: "group", ResourceID: id,
		Details: map[string]string{"from": old.Name, "to": name},
	})
	http.Redirect(w, r, "/groups/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

// SubmitDelete deletes a group (never its secrets or any grant).
func (h *GroupsHandler) SubmitDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	id, err := idParam(r)
	if err != nil {
		http.Error(w, "invalid group id", http.StatusBadRequest)
		return
	}
	old, err := h.groups.Get(r.Context(), id)
	if errors.Is(err, storage.ErrGroupNotFound) {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.groups.Delete(r.Context(), id); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	audit.Record(r.Context(), h.audit, audit.Event{
		Actor: audit.User(user.ID), Action: audit.GroupDelete, ResourceType: "group", ResourceID: id,
		Details: map[string]string{"name": old.Name},
	})
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}
