package api

import (
	"context"
	"errors"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// GroupsHandler implements secret groups: named sets of secrets that the
// web UI offers as one-click selections when editing a token's grants.
// Grants, tokens and /env know nothing about them. Session-only.
type GroupsHandler struct {
	groups *storage.GroupRepo
	audit  audit.Logger
}

// NewGroupsHandler returns a GroupsHandler backed by groups.
func NewGroupsHandler(groups *storage.GroupRepo, auditLog audit.Logger) *GroupsHandler {
	return &GroupsHandler{groups: groups, audit: auditLog}
}

// RegisterGroups registers the group operations on api (a session-only
// group).
func RegisterGroups(api huma.API, h *GroupsHandler) {
	const note = "Groups only help the web UI tick several secrets together; grants never reference them."
	huma.Register(api, huma.Operation{
		OperationID: "list-groups", Method: "GET", Path: "/groups",
		Summary: "List secret groups with their members", Description: note, Tags: []string{"groups"},
	}, h.List)
	huma.Register(api, huma.Operation{
		OperationID: "create-group", Method: "POST", Path: "/groups",
		Summary: "Create an empty secret group", Description: note, Tags: []string{"groups"},
	}, h.Create)
	huma.Register(api, huma.Operation{
		OperationID: "get-group", Method: "GET", Path: "/groups/{id}",
		Summary: "Get a secret group and its members", Tags: []string{"groups"},
	}, h.Get)
	huma.Register(api, huma.Operation{
		OperationID: "rename-group", Method: "PUT", Path: "/groups/{id}",
		Summary: "Rename a secret group", Tags: []string{"groups"},
	}, h.Rename)
	huma.Register(api, huma.Operation{
		OperationID: "delete-group", Method: "DELETE", Path: "/groups/{id}",
		Summary: "Delete a secret group", Description: "Removes the group only; its secrets and every grant are untouched.",
		Tags: []string{"groups"},
	}, h.Delete)
	huma.Register(api, huma.Operation{
		OperationID: "set-group-members", Method: "PUT", Path: "/groups/{id}/members",
		Summary: "Set a group's members", Description: "The listed secrets become the group's complete membership. A secret can be in any number of groups.",
		Tags: []string{"groups"},
	}, h.SetMembers)
}

// GroupOut is a group as returned by the API.
type GroupOut struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	SecretIDs []int64   `json:"secret_ids"`
}

func toGroupOut(g model.SecretGroup) GroupOut {
	ids := g.SecretIDs
	if ids == nil {
		ids = []int64{}
	}
	return GroupOut{ID: g.ID, Name: g.Name, CreatedAt: g.CreatedAt, SecretIDs: ids}
}

// GroupBody wraps one group.
type GroupBody struct{ Body GroupOut }

// GroupIDInput identifies a group.
type GroupIDInput struct {
	ID int64 `path:"id" doc:"Group ID"`
}

func groupErr(err error) error {
	switch {
	case errors.Is(err, storage.ErrGroupNotFound):
		return huma.Error404NotFound("group not found")
	case errors.Is(err, storage.ErrSecretNotFound):
		return huma.Error404NotFound("secret not found")
	case errors.Is(err, storage.ErrGroupNameTaken):
		return huma.Error409Conflict("a group with that name already exists")
	case errors.Is(err, storage.ErrInvalidGroupName):
		return huma.Error400BadRequest(err.Error())
	default:
		return huma.Error500InternalServerError("internal error", err)
	}
}

// ListGroupsOutput lists every group.
type ListGroupsOutput struct {
	Body struct {
		Groups []GroupOut `json:"groups"`
	}
}

// List returns every group.
func (h *GroupsHandler) List(ctx context.Context, _ *EmptyInput) (*ListGroupsOutput, error) {
	groups, err := h.groups.List(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	out := &ListGroupsOutput{}
	out.Body.Groups = []GroupOut{}
	for _, g := range groups {
		out.Body.Groups = append(out.Body.Groups, toGroupOut(g))
	}
	return out, nil
}

// GroupNameInput carries a group name.
type GroupNameInput struct {
	Body struct {
		Name string `json:"name" minLength:"1" maxLength:"64"`
	}
}

// Create adds an empty group.
func (h *GroupsHandler) Create(ctx context.Context, in *GroupNameInput) (*GroupBody, error) {
	g, err := h.groups.Create(ctx, in.Body.Name)
	if err != nil {
		return nil, groupErr(err)
	}
	audit.Record(ctx, h.audit, audit.Event{
		Actor: actorFrom(ctx), Action: audit.GroupCreate, ResourceType: "group", ResourceID: g.ID,
		Details: map[string]string{"name": g.Name},
	})
	return &GroupBody{Body: toGroupOut(g)}, nil
}

// Get returns one group.
func (h *GroupsHandler) Get(ctx context.Context, in *GroupIDInput) (*GroupBody, error) {
	g, err := h.groups.Get(ctx, in.ID)
	if err != nil {
		return nil, groupErr(err)
	}
	return &GroupBody{Body: toGroupOut(g)}, nil
}

// RenameInput renames a group.
type RenameInput struct {
	ID   int64 `path:"id" doc:"Group ID"`
	Body struct {
		Name string `json:"name" minLength:"1" maxLength:"64"`
	}
}

// Rename changes a group's name.
func (h *GroupsHandler) Rename(ctx context.Context, in *RenameInput) (*GroupBody, error) {
	old, err := h.groups.Get(ctx, in.ID)
	if err != nil {
		return nil, groupErr(err)
	}
	if err := h.groups.Rename(ctx, in.ID, in.Body.Name); err != nil {
		return nil, groupErr(err)
	}
	g, err := h.groups.Get(ctx, in.ID)
	if err != nil {
		return nil, groupErr(err)
	}
	audit.Record(ctx, h.audit, audit.Event{
		Actor: actorFrom(ctx), Action: audit.GroupRename, ResourceType: "group", ResourceID: g.ID,
		Details: map[string]string{"from": old.Name, "to": g.Name},
	})
	return &GroupBody{Body: toGroupOut(g)}, nil
}

// Delete removes a group (never its secrets or any grant).
func (h *GroupsHandler) Delete(ctx context.Context, in *GroupIDInput) (*struct{}, error) {
	old, err := h.groups.Get(ctx, in.ID)
	if err != nil {
		return nil, groupErr(err)
	}
	if err := h.groups.Delete(ctx, in.ID); err != nil {
		return nil, groupErr(err)
	}
	audit.Record(ctx, h.audit, audit.Event{
		Actor: actorFrom(ctx), Action: audit.GroupDelete, ResourceType: "group", ResourceID: in.ID,
		Details: map[string]string{"name": old.Name},
	})
	return &struct{}{}, nil
}

// SetMembersInput is a group's complete membership.
type SetMembersInput struct {
	ID   int64 `path:"id" doc:"Group ID"`
	Body struct {
		SecretIDs []int64 `json:"secret_ids"`
	}
}

// SetMembers replaces a group's membership.
func (h *GroupsHandler) SetMembers(ctx context.Context, in *SetMembersInput) (*struct{}, error) {
	if err := h.groups.SetMembers(ctx, in.ID, in.Body.SecretIDs); err != nil {
		return nil, groupErr(err)
	}
	audit.Record(ctx, h.audit, audit.Event{
		Actor: actorFrom(ctx), Action: audit.GroupMembers, ResourceType: "group", ResourceID: in.ID,
		Details: map[string]string{"count": itoa(int64(len(in.Body.SecretIDs)))},
	})
	return &struct{}{}, nil
}
