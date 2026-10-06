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

// GroupsHandler implements the admin group-management pages.
type GroupsHandler struct {
	groups *storage.GroupRepo
	audit  audit.Logger
}

// NewGroupsHandler returns a GroupsHandler backed by groups.
func NewGroupsHandler(groups *storage.GroupRepo, auditLog audit.Logger) *GroupsHandler {
	return &GroupsHandler{groups: groups, audit: auditLog}
}

type groupsPage struct {
	basePage
	Groups []model.Group
}

// List shows every group and the create-group form.
func (h *GroupsHandler) List(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	groups, err := h.groups.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	render(w, http.StatusOK, "groups", groupsPage{basePage: basePage{User: &user}, Groups: groups})
}

// SubmitCreate creates a new group.
func (h *GroupsHandler) SubmitCreate(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	g, err := h.groups.Create(r.Context(), r.FormValue("name"), r.FormValue("description"))
	if err != nil {
		http.Error(w, "could not create group (name may already be taken)", http.StatusBadRequest)
		return
	}
	audit.Record(r.Context(), h.audit, audit.Event{
		Actor: currentActor(r), Action: audit.GroupCreate, ResourceType: "group", ResourceID: g.ID,
		Details: map[string]string{"name": g.Name},
	})
	http.Redirect(w, r, "/admin/groups", http.StatusSeeOther)
}

type groupDetailPage struct {
	basePage
	Group   model.Group
	Members []model.GroupMember
}

// Detail shows a group's members and the add-member form.
func (h *GroupsHandler) Detail(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	id, err := idParam(r, "id")
	if err != nil {
		http.Error(w, "invalid group id", http.StatusBadRequest)
		return
	}

	g, err := h.groups.GetByID(r.Context(), id)
	if err != nil {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	members, err := h.groups.ListMembers(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	render(w, http.StatusOK, "group_detail", groupDetailPage{
		basePage: basePage{User: &user},
		Group:    g,
		Members:  members,
	})
}

// SubmitAddMember adds (or changes the role of) a group member.
func (h *GroupsHandler) SubmitAddMember(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		http.Error(w, "invalid group id", http.StatusBadRequest)
		return
	}
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	memberID, err := parseFormInt64(r, "user_id")
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	role := model.GroupRole(r.FormValue("role"))

	if err := h.groups.AddMember(r.Context(), id, memberID, role); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			http.Error(w, "no such user", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	audit.Record(r.Context(), h.audit, audit.Event{
		Actor: currentActor(r), Action: audit.GroupMemberAdd, ResourceType: "group", ResourceID: id,
		Details: map[string]string{"user_id": strconv.FormatInt(memberID, 10), "role": string(role)},
	})
	redirectToGroup(w, r, id)
}

// SubmitRemoveMember removes a group member.
func (h *GroupsHandler) SubmitRemoveMember(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		http.Error(w, "invalid group id", http.StatusBadRequest)
		return
	}
	userID, err := idParam(r, "userId")
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	if err := h.groups.RemoveMember(r.Context(), id, userID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	audit.Record(r.Context(), h.audit, audit.Event{
		Actor: currentActor(r), Action: audit.GroupMemberRemove, ResourceType: "group", ResourceID: id,
		Details: map[string]string{"user_id": strconv.FormatInt(userID, 10)},
	})
	redirectToGroup(w, r, id)
}
