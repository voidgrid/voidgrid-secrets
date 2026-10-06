package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	oidcclient "github.com/voidgrid/voidgrid-secrets/internal/auth/oidc"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/recoverycode"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// AuthConfigGetter is the subset of auth-config storage the login page
// needs, to know which method the deployment uses.
type AuthConfigGetter interface {
	Get(ctx context.Context) (model.AuthConfig, error)
}

// SessionStore is the subset of session storage the login/logout/OIDC
// flows need.
type SessionStore interface {
	session.SessionCreator
	Revoke(ctx context.Context, plaintext string) error
	// Authenticate identifies the session being ended, for the audit log.
	Authenticate(ctx context.Context, plaintext string) (model.User, error)
}

// RecoveryCodeStore is the subset of recovery-code storage the login flow
// needs: consuming a code at recovery login, and issuing a fresh batch on
// an OIDC user's first login (see OIDCCallback).
type RecoveryCodeStore interface {
	session.RecoveryCodeConsumer
	ReplaceForUser(ctx context.Context, userID int64, hashedCodes []string) error
}

// AuthHandler implements the web login/logout pages, including the OIDC
// redirect flow and the recovery-code fallback shared by both auth
// methods.
type AuthHandler struct {
	login         *session.LoginService
	sessions      SessionStore
	authConfig    AuthConfigGetter
	oidcProvider  *oidcclient.Provider
	oidcUsers     oidcclient.UserProvisioner
	recoveryCodes RecoveryCodeStore
	audit         audit.Logger
}

// NewAuthHandler returns an AuthHandler backed by the given dependencies.
func NewAuthHandler(
	login *session.LoginService,
	sessions SessionStore,
	authConfig AuthConfigGetter,
	oidcProvider *oidcclient.Provider,
	oidcUsers oidcclient.UserProvisioner,
	recoveryCodes RecoveryCodeStore,
	auditLog audit.Logger,
) *AuthHandler {
	return &AuthHandler{
		login:         login,
		sessions:      sessions,
		authConfig:    authConfig,
		oidcProvider:  oidcProvider,
		oidcUsers:     auditedProvisioner{next: oidcUsers, audit: auditLog},
		recoveryCodes: recoveryCodes,
		audit:         auditLog,
	}
}

type loginPage struct {
	basePage
	Username string
	// AuthMethod decides which form the template renders: the
	// password+TOTP fields, or an OIDC "sign in" link. Either way, a
	// recovery-code link is always shown.
	AuthMethod model.AuthMethod
}

// ShowLogin renders the login page appropriate to the deployment's
// configured auth method.
func (h *AuthHandler) ShowLogin(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.authConfig.Get(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	render(w, http.StatusOK, "login", loginPage{AuthMethod: cfg.AuthMethod})
}

// SubmitLogin authenticates the submitted credentials and, on success,
// sets the session cookie and redirects to the secrets browser.
func (h *AuthHandler) SubmitLogin(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	code := r.FormValue("totp_code")

	token, expiresAt, err := h.login.Login(r.Context(), username, password, code)
	if err != nil {
		status, msg := http.StatusUnauthorized, "invalid username, password, or TOTP code"
		if errors.Is(err, session.ErrTooManyAttempts) {
			status, msg = http.StatusTooManyRequests, tooManyAttemptsMessage
		}
		render(w, status, "login", loginPage{
			basePage:   basePage{Error: msg},
			Username:   username,
			AuthMethod: model.AuthPasswordTOTP,
		})
		return
	}

	session.SetCookie(w, token, expiresAt)
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}

// SubmitLogout revokes the current session (if any), clears the cookie,
// and redirects to the login page.
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

// StartOIDCLogin redirects to the configured OIDC provider to begin the
// auth-code+PKCE flow. If OIDC isn't configured, or the client couldn't
// be built (e.g. the issuer was unreachable when this server last tried),
// it sends the user to the recovery-code login instead of failing dead -
// the whole point of recovery codes is to keep working when OIDC can't.
func (h *AuthHandler) StartOIDCLogin(w http.ResponseWriter, r *http.Request) {
	client, ok := h.oidcProvider.Get()
	if !ok {
		http.Redirect(w, r, "/login/recovery?error=oidc_unavailable", http.StatusSeeOther)
		return
	}
	client.LoginHandler()(w, r)
}

// OIDCCallback handles the provider's redirect callback: completes the
// code exchange, provisions (or finds) the local user, creates a session,
// and either shows a one-time recovery-codes page (first login for this
// user) or redirects straight to the secrets browser.
func (h *AuthHandler) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	client, ok := h.oidcProvider.Get()
	if !ok {
		http.Redirect(w, r, "/login/recovery?error=oidc_unavailable", http.StatusSeeOther)
		return
	}
	client.CallbackHandler(h.oidcUsers, h.onOIDCProvisioned)(w, r)
}

// onOIDCProvisioned creates a session for userID and, if this is their
// first login, also issues and displays a fresh batch of recovery codes
// instead of redirecting straight in - this is the earliest point an
// OIDC user has a user row at all to attach codes to, since OIDC setup
// itself creates no user (see setup.Wizard.SetupOIDC).
func (h *AuthHandler) onOIDCProvisioned(w http.ResponseWriter, r *http.Request, userID int64, created bool) {
	token, expiresAt, err := h.sessions.Create(r.Context(), userID, session.DefaultTTL)
	if err != nil {
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}
	session.SetCookie(w, token, expiresAt)
	audit.Record(r.Context(), h.audit, audit.Event{
		Actor: audit.User(userID), Action: audit.Login, ResourceType: "user", ResourceID: userID,
		Details: map[string]string{"method": "oidc"},
	})

	if !created {
		continueSignIn(w)
		return
	}

	codes, err := recoverycode.Generate()
	if err != nil {
		// The session cookie is already set, so the user is signed in
		// either way; this only skips showing a recovery-code batch.
		continueSignIn(w)
		return
	}
	hashed := make([]string, len(codes))
	for i, c := range codes {
		hashed[i] = crypto.HashToken(c)
	}
	if err := h.recoveryCodes.ReplaceForUser(r.Context(), userID, hashed); err != nil {
		continueSignIn(w)
		return
	}

	render(w, http.StatusOK, "recovery_codes", recoveryCodesPage{
		Codes:      codes,
		ContinueTo: "/secrets",
	})
}

// continueSignIn finishes an OIDC sign-in with a page that refreshes to
// /secrets, instead of an HTTP redirect. The session cookie is
// SameSite=Strict, and browsers treat a redirect chain that started at the
// identity provider as cross-site, so a plain redirect would arrive at
// /secrets without the cookie it just set. A refresh initiated by this
// page is a same-site navigation, so the cookie goes along.
const tooManyAttemptsMessage = "too many failed sign-in attempts for this account - try again in 15 minutes"

func continueSignIn(w http.ResponseWriter) {
	render(w, http.StatusOK, "signin_continue", basePage{RefreshTo: "/secrets"})
}

type recoveryLoginPage struct {
	basePage
	Username string
}

// ShowRecoveryLogin renders the recovery-code login form.
func (h *AuthHandler) ShowRecoveryLogin(w http.ResponseWriter, r *http.Request) {
	page := recoveryLoginPage{}
	if r.URL.Query().Get("error") == "oidc_unavailable" {
		page.basePage = basePage{Error: "OIDC sign-in is currently unavailable. Use a recovery code instead."}
	}
	render(w, http.StatusOK, "login_recovery", page)
}

// SubmitRecoveryLogin authenticates username/code against the user's
// stored recovery codes and, on success, sets the session cookie and
// redirects to the secrets browser.
func (h *AuthHandler) SubmitRecoveryLogin(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := r.FormValue("username")
	code := r.FormValue("code")

	token, expiresAt, err := h.login.LoginWithRecoveryCode(r.Context(), username, code)
	if err != nil {
		status, msg := http.StatusUnauthorized, "invalid username or recovery code"
		if errors.Is(err, session.ErrTooManyAttempts) {
			status, msg = http.StatusTooManyRequests, tooManyAttemptsMessage
		}
		render(w, status, "login_recovery", recoveryLoginPage{
			basePage: basePage{Error: msg},
			Username: username,
		})
		return
	}

	session.SetCookie(w, token, expiresAt)
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}
