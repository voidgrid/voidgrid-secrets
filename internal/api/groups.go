package api

import (
	"context"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// GroupsHandler implements admin-only group management. Mounted under
// /api/v1/admin.
type GroupsHandler struct {
	groups *storage.GroupRepo
}

// NewGroupsHandler returns a GroupsHandler backed by groups.
func NewGroupsHandler(groups *storage.GroupRepo) *GroupsHandler {
	return &GroupsHandler{groups: groups}
}

// RegisterGroups registers the admin group-management operations on api.
func RegisterGroups(api huma.API, h *GroupsHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-list-groups",
		Method:      "GET",
		Path:        "/admin/groups",
		Summary:     "List all groups",
		Tags:        []string{"admin"},
	}, h.List)

	huma.Register(api, huma.Operation{
		OperationID: "admin-create-group",
		Method:      "POST",
		Path:        "/admin/groups",
		Summary:     "Create a new group",
		Tags:        []string{"admin"},
	}, h.Create)

	huma.Register(api, huma.Operation{
		OperationID: "admin-list-group-members",
		Method:      "GET",
		Path:        "/admin/groups/{id}/members",
		Summary:     "List a group's members",
		Tags:        []string{"admin"},
	}, h.ListMembers)

	huma.Register(api, huma.Operation{
		OperationID: "admin-add-group-member",
		Method:      "POST",
		Path:        "/admin/groups/{id}/members",
		Summary:     "Add (or change the role of) a group member",
		Tags:        []string{"admin"},
	}, h.AddMember)

	huma.Register(api, huma.Operation{
		OperationID: "admin-remove-group-member",
		Method:      "DELETE",
		Path:        "/admin/groups/{id}/members/{userId}",
		Summary:     "Remove a group member",
		Tags:        []string{"admin"},
	}, h.RemoveMember)
}

// GroupOut is the API representation of a group.
type GroupOut struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

func toGroupOut(g model.Group) GroupOut {
	return GroupOut{ID: g.ID, Name: g.Name, Description: g.Description, CreatedAt: g.CreatedAt}
}

// ListGroupsOutput wraps the full group list.
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
	for _, g := range groups {
		out.Body.Groups = append(out.Body.Groups, toGroupOut(g))
	}
	return out, nil
}

// CreateGroupInput carries a new group's name/description.
type CreateGroupInput struct {
	Body struct {
		Name        string `json:"name" minLength:"1"`
		Description string `json:"description"`
	}
}

// CreateGroupOutput wraps the created group.
type CreateGroupOutput struct {
	Body GroupOut
}

// Create makes a new group.
func (h *GroupsHandler) Create(ctx context.Context, in *CreateGroupInput) (*CreateGroupOutput, error) {
	g, err := h.groups.Create(ctx, in.Body.Name, in.Body.Description)
	if err != nil {
		return nil, huma.Error409Conflict("could not create group (name may already be taken)", err)
	}
	return &CreateGroupOutput{Body: toGroupOut(g)}, nil
}

// GroupIDInput identifies a group by its path ID.
type GroupIDInput struct {
	ID int64 `path:"id" doc:"Group ID"`
}

// GroupMemberOut is the API representation of a group member.
type GroupMemberOut struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

// ListGroupMembersOutput wraps a group's member list.
type ListGroupMembersOutput struct {
	Body struct {
		Members []GroupMemberOut `json:"members"`
	}
}

// ListMembers returns a group's members.
func (h *GroupsHandler) ListMembers(ctx context.Context, in *GroupIDInput) (*ListGroupMembersOutput, error) {
	members, err := h.groups.ListMembers(ctx, in.ID)
	if err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	out := &ListGroupMembersOutput{}
	for _, m := range members {
		out.Body.Members = append(out.Body.Members, GroupMemberOut{UserID: m.UserID, Username: m.Username, Role: string(m.Role)})
	}
	return out, nil
}

// AddGroupMemberInput carries the user and role to add.
type AddGroupMemberInput struct {
	ID   int64 `path:"id" doc:"Group ID"`
	Body struct {
		UserID int64  `json:"user_id"`
		Role   string `json:"role" enum:"member,admin"`
	}
}

// AddGroupMemberOutput is empty: success is signaled by a 2xx status.
type AddGroupMemberOutput struct{}

// AddMember adds (or changes the role of) a group member.
func (h *GroupsHandler) AddMember(ctx context.Context, in *AddGroupMemberInput) (*AddGroupMemberOutput, error) {
	if err := h.groups.AddMember(ctx, in.ID, in.Body.UserID, model.GroupRole(in.Body.Role)); err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	return &AddGroupMemberOutput{}, nil
}

// RemoveGroupMemberInput identifies a group and member to remove.
type RemoveGroupMemberInput struct {
	ID     int64 `path:"id" doc:"Group ID"`
	UserID int64 `path:"userId" doc:"User ID to remove"`
}

// RemoveGroupMemberOutput is empty: success is signaled by a 2xx status.
type RemoveGroupMemberOutput struct{}

// RemoveMember removes a group member.
func (h *GroupsHandler) RemoveMember(ctx context.Context, in *RemoveGroupMemberInput) (*RemoveGroupMemberOutput, error) {
	if err := h.groups.RemoveMember(ctx, in.ID, in.UserID); err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	return &RemoveGroupMemberOutput{}, nil
}
