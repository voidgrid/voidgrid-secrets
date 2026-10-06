package api

import (
	"context"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/totp"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// UsersHandler implements admin-only user management. Mounted under
// /api/v1/admin, so every operation here requires an authenticated admin
// session (see sessionAuthMiddleware + adminOnlyMiddleware) - never a
// machine token.
type UsersHandler struct {
	users *storage.UserRepo
	audit audit.Logger
}

// NewUsersHandler returns a UsersHandler backed by users.
func NewUsersHandler(users *storage.UserRepo, auditLog audit.Logger) *UsersHandler {
	return &UsersHandler{users: users, audit: auditLog}
}

// RegisterUsers registers the admin user-management operations on api.
func RegisterUsers(api huma.API, h *UsersHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-list-users",
		Method:      "GET",
		Path:        "/admin/users",
		Summary:     "List all users",
		Tags:        []string{"admin"},
	}, h.List)

	huma.Register(api, huma.Operation{
		OperationID: "admin-create-user",
		Method:      "POST",
		Path:        "/admin/users",
		Summary:     "Create a new password+TOTP user",
		Tags:        []string{"admin"},
	}, h.Create)

	huma.Register(api, huma.Operation{
		OperationID: "admin-set-user-disabled",
		Method:      "PUT",
		Path:        "/admin/users/{id}/disabled",
		Summary:     "Enable or disable a user's account",
		Tags:        []string{"admin"},
	}, h.SetDisabled)
}

// UserOut is the API representation of a user, never including credentials.
type UserOut struct {
	ID         int64     `json:"id"`
	Username   string    `json:"username"`
	AuthMethod string    `json:"auth_method"`
	Disabled   bool      `json:"disabled"`
	IsAdmin    bool      `json:"is_admin"`
	CreatedAt  time.Time `json:"created_at"`
}

func toUserOut(u model.User) UserOut {
	return UserOut{
		ID:         u.ID,
		Username:   u.Username,
		AuthMethod: string(u.AuthMethod),
		Disabled:   u.Disabled,
		IsAdmin:    u.IsAdmin,
		CreatedAt:  u.CreatedAt,
	}
}

// ListUsersOutput wraps the full user list.
type ListUsersOutput struct {
	Body struct {
		Users []UserOut `json:"users"`
	}
}

// List returns every user.
func (h *UsersHandler) List(ctx context.Context, _ *EmptyInput) (*ListUsersOutput, error) {
	users, err := h.users.List(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	out := &ListUsersOutput{}
	for _, u := range users {
		out.Body.Users = append(out.Body.Users, toUserOut(u))
	}
	return out, nil
}

// CreateUserInput carries a new user's credentials.
type CreateUserInput struct {
	Body struct {
		Username string `json:"username" minLength:"1"`
		Password string `json:"password" minLength:"14"`
	}
}

// CreateUserOutput carries the new user and their TOTP enrollment details.
// Unlike the first-run wizard, no separate confirmation step is required:
// an admin creating an additional account is a lower-stakes operation than
// bootstrapping the only admin, and can simply recreate the account if
// enrollment goes wrong.
type CreateUserOutput struct {
	Body struct {
		User            UserOut `json:"user"`
		TOTPSecret      string  `json:"totp_secret"`
		ProvisioningURI string  `json:"provisioning_uri"`
	}
}

// Create makes a new password+TOTP user and enrolls their TOTP secret.
func (h *UsersHandler) Create(ctx context.Context, in *CreateUserInput) (*CreateUserOutput, error) {
	hash, err := crypto.HashPassword(in.Body.Password)
	if err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}

	user, err := h.users.CreateWithPassword(ctx, in.Body.Username, hash)
	if err != nil {
		return nil, huma.Error409Conflict("could not create user (username may already be taken)", err)
	}

	secret, uri, err := totp.Generate(in.Body.Username)
	if err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	if err := h.users.SetTOTPSecret(ctx, user.ID, secret); err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}

	audit.Record(ctx, h.audit, audit.Event{
		Actor: actorFrom(ctx), Action: audit.UserCreate, ResourceType: "user", ResourceID: user.ID,
		Details: map[string]string{"username": user.Username, "method": "password_totp"},
	})
	out := &CreateUserOutput{}
	out.Body.User = toUserOut(user)
	out.Body.TOTPSecret = secret
	out.Body.ProvisioningURI = uri
	return out, nil
}

// SetUserDisabledInput identifies a user and the desired disabled state.
type SetUserDisabledInput struct {
	ID   int64 `path:"id"`
	Body struct {
		Disabled bool `json:"disabled"`
	}
}

// SetUserDisabledOutput is empty: success is signaled by a 2xx status.
type SetUserDisabledOutput struct{}

// SetDisabled enables or disables a user's account.
func (h *UsersHandler) SetDisabled(ctx context.Context, in *SetUserDisabledInput) (*SetUserDisabledOutput, error) {
	if err := h.users.SetDisabled(ctx, in.ID, in.Body.Disabled); err != nil {
		return nil, huma.Error404NotFound("user not found", err)
	}
	action := audit.UserEnable
	if in.Body.Disabled {
		action = audit.UserDisable
	}
	audit.Record(ctx, h.audit, audit.Event{Actor: actorFrom(ctx), Action: action, ResourceType: "user", ResourceID: in.ID})
	return &SetUserDisabledOutput{}, nil
}
