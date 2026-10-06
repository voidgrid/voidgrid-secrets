package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	oidcclient "github.com/voidgrid/voidgrid-secrets/internal/auth/oidc"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/setup"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// AuthConfigGetter is the subset of auth-config storage the login page
// needs, to know which method the deployment uses.
type AuthConfigGetter interface {
	Get(ctx context.Context) (model.AuthConfig, error)
}

// SessionStore is the subset of session storage sign-in and sign-out need.
type SessionStore interface {
	session.SessionCreator
	Revoke(ctx context.Context, plaintext string) error
	// Authenticate identifies the session being ended, for the audit log.
	Authenticate(ctx context.Context, plaintext string) (model.User, error)
}

// OIDCOwnerChecker reports whether an OIDC identity is the account's.
type OIDCOwnerChecker interface {
	OIDCOwner(ctx context.Context, subject string) (model.User, error)
}

// AuthHandler implements sign-in and sign-out, including the OIDC
// redirect flow - which, during setup, is how the operator's identity
// becomes the account.
type AuthHandler struct {
	login        *session.LoginService
	sessions     SessionStore
	authConfig   AuthConfigGetter
	oidcProvider *oidcclient.Provider
	owner        OIDCOwnerChecker
	wizard       *setup.Wizard
	audit        audit.Logger
}

// NewAuthHandler returns an AuthHandler backed by the given dependencies.
func NewAuthHandler(
	login *session.LoginService,
	sessions SessionStore,
	authConfig AuthConfigGetter,
	oidcProvider *oidcclient.Provider,
	owner OIDCOwnerChecker,
	wizard *setup.Wizard,
	auditLog audit.Logger,
) *AuthHandler {
	return &AuthHandler{
		login: login, sessions: sessions, authConfig: authConfig, oidcProvider: oidcProvider,
		owner: owner, wizard: wizard, audit: auditLog,
	}
}

type loginPage struct {
	basePage
	Username string
	// AuthMethod decides which form the template renders: the
	// password+TOTP fields, or an OIDC "sign in" link. Either way, a
	// recovery link is always shown.
	AuthMethod model.AuthMethod
}

const tooManyAttemptsMessage = "too many failed attempts - try again in 15 minutes"

// ShowLogin renders the login page for the deployment's auth method.
func (h *AuthHandler) ShowLogin(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.authConfig.Get(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	page := loginPage{AuthMethod: cfg.AuthMethod}
	if r.URL.Query().Get("error") == "oidc_unavailable" {
		page.Error = "OIDC sign-in is unavailable right now (the provider couldn't be reached at startup). Use a recovery code to get in."
	}
	render(w, http.StatusOK, "login", page)
}

// SubmitLogin checks password+TOTP and, on success, sets the session
// cookie and goes to the secrets list.
func (h *AuthHandler) SubmitLogin(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := r.FormValue("username")
	token, expiresAt, err := h.login.Login(r.Context(), username, r.FormValue("password"), r.FormValue("totp_code"))
	if err != nil {
		status, msg := http.StatusUnauthorized, "invalid username, password, or TOTP code"
		if errors.Is(err, session.ErrTooManyAttempts) {
			status, msg = http.StatusTooManyRequests, tooManyAttemptsMessage
		}
		render(w, status, "login", loginPage{basePage: basePage{Error: msg}, Username: username, AuthMethod: model.AuthPasswordTOTP})
		return
	}
	session.SetCookie(w, token, expiresAt)
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}

// SubmitLogout ends the current session and clears the cookie.
func (h *AuthHandler) SubmitLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(session.CookieName); err == nil && cookie.Value != "" {
		if u, err := h.sessions.Authenticate(r.Context(), cookie.Value); err == nil {
			audit.Record(r.Context(), h.audit, audit.Event{Actor: audit.User(u.ID), Action: audit.Logout, ResourceType: "user", ResourceID: u.ID})
		}
		_ = h.sessions.Revoke(r.Context(), cookie.Value)
	}
	session.ClearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// StartOIDCLogin redirects to the OIDC provider. If the provider client
// isn't available (unreachable at startup), it points at recovery instead
// of failing dead.
func (h *AuthHandler) StartOIDCLogin(w http.ResponseWriter, r *http.Request) {
	client, ok := h.oidcProvider.Get()
	if !ok {
		http.Redirect(w, r, "/login?error=oidc_unavailable", http.StatusSeeOther)
		return
	}
	client.LoginHandler()(w, r)
}

// OIDCCallback handles the provider's redirect, both during setup (the
// identity becomes the account) and afterwards (only that identity may
// sign in).
func (h *AuthHandler) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	client, ok := h.oidcProvider.Get()
	if !ok {
		http.Redirect(w, r, "/login?error=oidc_unavailable", http.StatusSeeOther)
		return
	}
	client.CallbackHandler(h.onIdentity)(w, r)
}

func (h *AuthHandler) onIdentity(w http.ResponseWriter, r *http.Request, subject, preferredUsername string) {
	ctx := r.Context()
	complete, err := h.wizard.IsComplete(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !complete {
		h.claimDuringSetup(w, r, subject, preferredUsername)
		return
	}

	user, err := h.owner.OIDCOwner(ctx, subject)
	if errors.Is(err, storage.ErrNotOwner) {
		audit.Record(ctx, h.audit, audit.Event{
			Actor: audit.Anonymous(), Action: audit.LoginFailed, ResourceType: "user",
			Details: map[string]string{"method": "oidc", "subject": subject, "username": preferredUsername, "reason": "not the account owner"},
		})
		http.Error(w, "this identity isn't the account owner", http.StatusForbidden)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !h.startSession(w, r, user.ID) {
		return
	}
	audit.Record(ctx, h.audit, audit.Event{
		Actor: audit.User(user.ID), Action: audit.Login, ResourceType: "user", ResourceID: user.ID,
		Details: map[string]string{"method": "oidc"},
	})
	continueSignIn(w)
}

// claimDuringSetup makes the identity the account, using the setup token
// the operator entered on /setup/oidc (carried in setupCookie).
func (h *AuthHandler) claimDuringSetup(w http.ResponseWriter, r *http.Request, subject, preferredUsername string) {
	setupToken := ""
	if c, err := r.Cookie(setupCookie); err == nil {
		setupToken = c.Value
	}
	user, codes, err := h.wizard.ClaimOIDC(r.Context(), setupToken, subject, preferredUsername)
	if errors.Is(err, setup.ErrInvalidSetupToken) {
		http.Error(w, "setup isn't finished, and this sign-in didn't start from the setup page - go to /setup/oidc", http.StatusForbidden)
		return
	}
	if err != nil {
		http.Error(w, "could not finish setup: "+err.Error(), http.StatusInternalServerError)
		return
	}
	clearSetupCookie(w)
	if !h.startSession(w, r, user.ID) {
		return
	}
	// A page rather than a redirect: the Strict session cookie set in
	// this response isn't sent on a redirect that follows a cross-site
	// navigation (see continueSignIn); a click from this page is
	// same-site.
	render(w, http.StatusOK, "recovery_codes", recoveryCodesPage{Codes: codes, ContinueTo: "/secrets"})
}

func (h *AuthHandler) startSession(w http.ResponseWriter, r *http.Request, userID int64) bool {
	token, expiresAt, err := h.sessions.Create(r.Context(), userID, session.DefaultTTL)
	if err != nil {
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return false
	}
	session.SetCookie(w, token, expiresAt)
	return true
}

// continueSignIn finishes an OIDC sign-in with a page that refreshes to
// /secrets instead of a redirect: the provider's redirect here is a
// cross-site navigation, and a SameSite=Strict cookie set during it isn't
// sent on a redirect that continues it, so the user would look signed out.
func continueSignIn(w http.ResponseWriter) {
	render(w, http.StatusOK, "signin_continue", basePage{RefreshTo: "/secrets"})
}
