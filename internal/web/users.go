package web

import (
	"fmt"
	"net/http"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/totp"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// UsersHandler implements the admin user-management pages.
type UsersHandler struct {
	users *storage.UserRepo
}

// NewUsersHandler returns a UsersHandler backed by users.
func NewUsersHandler(users *storage.UserRepo) *UsersHandler {
	return &UsersHandler{users: users}
}

type newUserTOTP struct {
	Username        string
	Secret          string
	ProvisioningURI string
}

type usersPage struct {
	basePage
	Users       []model.User
	NewUserTOTP *newUserTOTP
}

// List shows every user and the create-user form.
func (h *UsersHandler) List(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	users, err := h.users.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	render(w, http.StatusOK, "users", usersPage{basePage: basePage{User: &user}, Users: users})
}

// SubmitCreate creates a new password+TOTP user and shows their enrollment
// details once. No separate confirmation step is required here (unlike the
// first-run wizard): an admin creating an additional account is lower
// stakes than bootstrapping the only admin.
func (h *UsersHandler) SubmitCreate(w http.ResponseWriter, r *http.Request) {
	admin, _ := session.FromContext(r.Context())
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	if len(password) < crypto.MinPasswordLength {
		h.renderWithError(w, r, admin, fmt.Sprintf("password must be at least %d characters", crypto.MinPasswordLength))
		return
	}

	hash, err := crypto.HashPassword(password)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	newUser, err := h.users.CreateWithPassword(r.Context(), username, hash)
	if err != nil {
		h.renderWithError(w, r, admin, "could not create user (username may already be taken)")
		return
	}
	secret, uri, err := totp.Generate(username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.users.SetTOTPSecret(r.Context(), newUser.ID, secret); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	users, err := h.users.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	render(w, http.StatusOK, "users", usersPage{
		basePage:    basePage{User: &admin},
		Users:       users,
		NewUserTOTP: &newUserTOTP{Username: username, Secret: secret, ProvisioningURI: uri},
	})
}

// SubmitSetDisabled enables or disables a user's account.
func (h *UsersHandler) SubmitSetDisabled(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	disabled := r.FormValue("disabled") == "true"

	if err := h.users.SetDisabled(r.Context(), id, disabled); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (h *UsersHandler) renderWithError(w http.ResponseWriter, r *http.Request, admin model.User, msg string) {
	users, err := h.users.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	render(w, http.StatusBadRequest, "users", usersPage{basePage: basePage{User: &admin, Error: msg}, Users: users})
}
