package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
)

// SessionRevoker is the subset of session storage the logout handler needs.
type SessionRevoker interface {
	Revoke(ctx context.Context, plaintext string) error
}

// AuthHandler implements login and logout for the password+TOTP web
// authentication method.
type AuthHandler struct {
	login    *session.LoginService
	sessions SessionRevoker
}

// NewAuthHandler returns an AuthHandler backed by login and sessions.
func NewAuthHandler(login *session.LoginService, sessions SessionRevoker) *AuthHandler {
	return &AuthHandler{login: login, sessions: sessions}
}

// RegisterAuth registers the login/logout operations on api.
func RegisterAuth(api huma.API, h *AuthHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "login",
		Method:      "POST",
		Path:        "/auth/login",
		Summary:     "Log in with username, password, and TOTP code",
		Tags:        []string{"auth"},
	}, h.Login)

	huma.Register(api, huma.Operation{
		OperationID: "logout",
		Method:      "POST",
		Path:        "/auth/logout",
		Summary:     "Log out, revoking the current session",
		Tags:        []string{"auth"},
	}, h.Logout)
}

// LoginInput carries login credentials. TOTPCode is always required: the
// password+TOTP method has no bypass.
type LoginInput struct {
	Body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
}

// LoginOutput sets the session cookie on success.
type LoginOutput struct {
	SetCookie string `header:"Set-Cookie"`
}

// Login authenticates the given credentials and, on success, returns a
// Set-Cookie header establishing a session.
func (h *AuthHandler) Login(ctx context.Context, in *LoginInput) (*LoginOutput, error) {
	token, expiresAt, err := h.login.Login(ctx, in.Body.Username, in.Body.Password, in.Body.TOTPCode)
	if err != nil {
		if errors.Is(err, session.ErrTooManyAttempts) {
			return nil, huma.Error429TooManyRequests("too many failed login attempts for this account, try again later")
		}
		return nil, huma.Error401Unauthorized("invalid username, password, or TOTP code")
	}

	cookie := &http.Cookie{
		Name:     session.CookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	return &LoginOutput{SetCookie: cookie.String()}, nil
}

// LogoutInput reads the current session cookie, if any. The literal string
// must match session.CookieName (struct tags require a compile-time
// constant).
type LogoutInput struct {
	Session string `cookie:"vgs_session"`
}

// LogoutOutput clears the session cookie.
type LogoutOutput struct {
	SetCookie string `header:"Set-Cookie"`
}

// Logout revokes the current session (if any) and clears the cookie.
// Logging out with no session, or an already-invalid one, is not an error:
// the end state (logged out) is the same either way.
func (h *AuthHandler) Logout(ctx context.Context, in *LogoutInput) (*LogoutOutput, error) {
	if in.Session != "" {
		_ = h.sessions.Revoke(ctx, in.Session)
	}

	cookie := &http.Cookie{
		Name:     session.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	return &LogoutOutput{SetCookie: cookie.String()}, nil
}
