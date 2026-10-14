package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	oidcclient "github.com/voidgrid/voidgrid-secrets/internal/auth/oidc"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// reauthMaxAge is how recent the provider's auth_time must be for an OIDC
// re-authentication to count: it must have asked for credentials just now.
const reauthMaxAge = 2 * time.Minute

// Reauthenticator re-checks the signed-in password account.
type Reauthenticator interface {
	Reauth(ctx context.Context, username, password, totpCode string) error
}

// RecoveryCodeIssuer replaces the account's recovery codes.
type RecoveryCodeIssuer interface {
	RegenerateCodes(ctx context.Context, userID int64, method string) ([]string, error)
	UnusedCodes(ctx context.Context, userID int64) (int, error)
}

// AccountHandler serves the account page: today, issuing a fresh set of
// recovery codes after the account proves it is still the one signed in.
// A password account re-enters its password and a current TOTP code; an
// OIDC account signs in at the provider again (prompt=login) and must come
// back as the same identity.
type AccountHandler struct {
	login        Reauthenticator
	codes        RecoveryCodeIssuer
	owner        OIDCOwnerChecker
	oidcProvider *oidcclient.Provider
	audit        audit.Logger
	now          func() time.Time
}

// NewAccountHandler returns an AccountHandler backed by the given
// dependencies.
func NewAccountHandler(login Reauthenticator, codes RecoveryCodeIssuer, owner OIDCOwnerChecker, oidcProvider *oidcclient.Provider, auditLog audit.Logger) *AccountHandler {
	return &AccountHandler{login: login, codes: codes, owner: owner, oidcProvider: oidcProvider, audit: auditLog, now: time.Now}
}

type accountPage struct {
	basePage
	AuthMethod model.AuthMethod
	// Unused is how many recovery codes the account has left.
	Unused int
}

// Show renders the account page.
func (h *AccountHandler) Show(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	h.render(w, r, user, http.StatusOK, "")
}

func (h *AccountHandler) render(w http.ResponseWriter, r *http.Request, user model.User, status int, msg string) {
	unused, err := h.codes.UnusedCodes(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	render(w, status, "account", accountPage{basePage: basePage{User: &user, Error: msg}, AuthMethod: user.AuthMethod, Unused: unused})
}

// SubmitRegenerate re-authenticates a password account and replaces its
// recovery codes. The old codes stop working at once.
func (h *AccountHandler) SubmitRegenerate(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	if user.AuthMethod != model.AuthPasswordTOTP {
		h.render(w, r, user, http.StatusBadRequest, "this account signs in with OIDC - use the provider re-sign-in below")
		return
	}
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	err := h.login.Reauth(r.Context(), user.Username, r.FormValue("password"), r.FormValue("totp_code"))
	switch {
	case err == nil:
	case errors.Is(err, session.ErrTooManyAttempts):
		h.render(w, r, user, http.StatusTooManyRequests, tooManyAttemptsMessage)
		return
	case errors.Is(err, session.ErrInvalidCredentials):
		h.render(w, r, user, http.StatusUnauthorized, "wrong password or TOTP code")
		return
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.issue(w, r, user.ID, "password")
}

// StartOIDCReauth sends an OIDC account to the provider to sign in again.
func (h *AccountHandler) StartOIDCReauth(w http.ResponseWriter, r *http.Request) {
	user, _ := session.FromContext(r.Context())
	if user.AuthMethod != model.AuthOIDC {
		h.render(w, r, user, http.StatusBadRequest, "this account signs in with a password - use the form below")
		return
	}
	client, ok := h.oidcProvider.Get()
	if !ok {
		h.render(w, r, user, http.StatusServiceUnavailable, "the OIDC provider couldn't be reached at startup")
		return
	}
	client.ReauthLoginHandler()(w, r)
}

// FinishOIDCReauth completes a re-authentication started by
// StartOIDCReauth (the shared OIDC callback routes it here by its state).
// The identity must be the account's, and the provider must say it
// authenticated the user moments ago. The browser arrives from another
// site, so the Strict session cookie isn't sent: the state cookie that
// only StartOIDCReauth (behind a session) sets is what ties this to a
// signed-in browser.
func (h *AccountHandler) FinishOIDCReauth(w http.ResponseWriter, r *http.Request, id oidcclient.Identity) {
	ctx := r.Context()
	user, err := h.owner.OIDCOwner(ctx, id.Subject)
	if errors.Is(err, storage.ErrNotOwner) {
		audit.Record(ctx, h.audit, audit.Event{
			Actor: audit.Anonymous(), Action: audit.ReauthFailed, ResourceType: "user",
			Details: map[string]string{"method": "oidc", "subject": id.Subject, "reason": "not the account owner"},
		})
		http.Error(w, "this identity isn't the account owner", http.StatusForbidden)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// max_age=0 obliges a compliant provider to include auth_time; one that
	// doesn't, or whose time is stale, did not just ask for credentials.
	age := h.now().Sub(id.AuthTime)
	if id.AuthTime.IsZero() || age > reauthMaxAge || age < -reauthMaxAge {
		reason := "provider reported no auth_time"
		if !id.AuthTime.IsZero() {
			reason = "sign-in at the provider was not recent"
		}
		audit.Record(ctx, h.audit, audit.Event{
			Actor: audit.User(user.ID), Action: audit.ReauthFailed, ResourceType: "user", ResourceID: user.ID,
			Details: map[string]string{"method": "oidc", "reason": reason},
		})
		http.Error(w, "the provider did not confirm a fresh sign-in ("+reason+"), so no codes were issued", http.StatusForbidden)
		return
	}
	audit.Record(ctx, h.audit, audit.Event{Actor: audit.User(user.ID), Action: audit.Reauth, ResourceType: "user", ResourceID: user.ID, Details: map[string]string{"method": "oidc"}})
	h.issue(w, r, user.ID, "oidc")
}

func (h *AccountHandler) issue(w http.ResponseWriter, r *http.Request, userID int64, method string) {
	codes, err := h.codes.RegenerateCodes(r.Context(), userID, method)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	render(w, http.StatusOK, "recovery_codes", recoveryCodesPage{Codes: codes, ContinueTo: "/account"})
}
