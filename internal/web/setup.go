package web

import (
	"fmt"
	"net/http"
	"time"

	oidcclient "github.com/voidgrid/voidgrid-secrets/internal/auth/oidc"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/setup"
)

// SetupHandler implements the first-run setup wizard's web pages.
type SetupHandler struct {
	wizard       *setup.Wizard
	oidcProvider *oidcclient.Provider
}

// NewSetupHandler returns a SetupHandler backed by w. A successful OIDC
// setup installs the newly built client into oidcProvider, so login works
// immediately without waiting for a server restart.
func NewSetupHandler(w *setup.Wizard, oidcProvider *oidcclient.Provider) *SetupHandler {
	return &SetupHandler{wizard: w, oidcProvider: oidcProvider}
}

type setupInitPage struct {
	basePage
}

// ShowInit renders the first step: create the admin account, or switch to
// OIDC setup instead.
func (h *SetupHandler) ShowInit(w http.ResponseWriter, _ *http.Request) {
	render(w, http.StatusOK, "setup_init", setupInitPage{})
}

type setupConfirmPage struct {
	basePage
	// SetupToken is carried to the confirm step in a hidden field, since
	// that step needs it too.
	SetupToken      string
	Username        string
	Secret          string
	ProvisioningURI string
	QRCodeDataURI   string
}

// SubmitInit creates the admin account and shows the TOTP enrollment step.
func (h *SetupHandler) SubmitInit(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	setupToken := r.FormValue("setup_token")
	username := r.FormValue("username")
	password := r.FormValue("password")

	if len(password) < crypto.MinPasswordLength {
		render(w, http.StatusBadRequest, "setup_init", setupInitPage{
			basePage: basePage{Error: fmt.Sprintf("password must be at least %d characters", crypto.MinPasswordLength)},
		})
		return
	}

	secret, uri, err := h.wizard.InitPasswordSetup(r.Context(), setupToken, username, password)
	if err != nil {
		render(w, http.StatusBadRequest, "setup_init", setupInitPage{basePage: basePage{Error: err.Error()}})
		return
	}

	qrDataURI, err := qrCodeDataURI(uri)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	render(w, http.StatusOK, "setup_confirm", setupConfirmPage{
		SetupToken:      setupToken,
		Username:        username,
		Secret:          secret,
		ProvisioningURI: uri,
		QRCodeDataURI:   qrDataURI,
	})
}

// recoveryCodesPage renders a one-time display of a freshly issued batch
// of recovery codes - shown exactly once, since only their hash is ever
// stored afterward. Shared between the password+TOTP setup-completion
// step and the OIDC first-login step (see AuthHandler.OIDCCallback).
type recoveryCodesPage struct {
	basePage
	Codes      []string
	ContinueTo string
}

// SubmitConfirm validates the admin's TOTP code, completes setup, and
// shows the resulting one-time batch of recovery codes.
func (h *SetupHandler) SubmitConfirm(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	setupToken := r.FormValue("setup_token")
	username := r.FormValue("username")
	code := r.FormValue("code")

	codes, err := h.wizard.ConfirmPasswordSetup(r.Context(), setupToken, username, code)
	if err != nil {
		render(w, http.StatusBadRequest, "setup_confirm", setupConfirmPage{
			basePage:   basePage{Error: err.Error()},
			SetupToken: setupToken,
			Username:   username,
		})
		return
	}

	render(w, http.StatusOK, "recovery_codes", recoveryCodesPage{
		Codes:      codes,
		ContinueTo: "/login",
	})
}

type setupOIDCPage struct {
	basePage
	SuggestedRedirectURI string
}

// ShowOIDCSetup renders the OIDC configuration step, prefilling the
// callback URL an admin would register with their provider from the
// request's own host - still editable, since a deployment behind a
// reverse proxy may need a different one.
func (h *SetupHandler) ShowOIDCSetup(w http.ResponseWriter, r *http.Request) {
	render(w, http.StatusOK, "setup_oidc", setupOIDCPage{
		SuggestedRedirectURI: suggestedRedirectURI(r),
	})
}

// SubmitOIDCSetup configures OIDC as the deployment's auth method. It
// validates the issuer by actually performing OIDC discovery before
// storing anything - failing fast here, at setup time, beats silently
// storing a config that can never work - and installs the resulting
// client immediately so login works without a restart.
func (h *SetupHandler) SubmitOIDCSetup(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	setupToken := r.FormValue("setup_token")
	issuer := r.FormValue("issuer")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	redirectURI := r.FormValue("redirect_uri")

	// Checked before discovery, so nobody without the token can make this
	// server fetch an arbitrary URL.
	if err := h.wizard.CheckSetupToken(r.Context(), setupToken); err != nil {
		render(w, http.StatusForbidden, "setup_oidc", setupOIDCPage{
			basePage:             basePage{Error: err.Error()},
			SuggestedRedirectURI: redirectURI,
		})
		return
	}

	client, err := oidcclient.New(r.Context(), oidcclient.Config{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
	})
	if err != nil {
		render(w, http.StatusBadRequest, "setup_oidc", setupOIDCPage{
			basePage:             basePage{Error: "failed to discover OIDC issuer - check the issuer URL and that this server can reach it"},
			SuggestedRedirectURI: redirectURI,
		})
		return
	}

	if err := h.wizard.SetupOIDC(r.Context(), setupToken, issuer, clientID, clientSecret, redirectURI); err != nil {
		render(w, http.StatusBadRequest, "setup_oidc", setupOIDCPage{
			basePage:             basePage{Error: err.Error()},
			SuggestedRedirectURI: redirectURI,
		})
		return
	}

	h.oidcProvider.Set(client)

	// Setup finishes when the operator signs in through the provider; the
	// setup token rides along in a short-lived cookie so the callback can
	// prove this sign-in started here.
	http.SetCookie(w, &http.Cookie{
		Name: setupCookie, Value: setupToken, Path: "/", MaxAge: int(setupCookieTTL / time.Second),
		HttpOnly: true, Secure: true,
		// Lax, not Strict: it has to arrive on the provider's redirect
		// back, which is a cross-site navigation.
		SameSite: http.SameSiteLaxMode,
	})
	render(w, http.StatusOK, "setup_oidc_done", setupInitPage{})
}

// setupCookie carries the setup token through the OIDC sign-in that
// finishes setup.
const (
	setupCookie    = "vgs_setup"
	setupCookieTTL = 15 * time.Minute
)

// StartOIDCClaim begins the OIDC sign-in that finishes setup.
func (h *SetupHandler) StartOIDCClaim(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie(setupCookie); err != nil {
		http.Redirect(w, r, "/setup/oidc", http.StatusSeeOther)
		return
	}
	client, ok := h.oidcProvider.Get()
	if !ok {
		http.Redirect(w, r, "/setup/oidc", http.StatusSeeOther)
		return
	}
	client.LoginHandler()(w, r)
}

func clearSetupCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: setupCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

// suggestedRedirectURI builds a best-guess callback URL from the
// request's own scheme/host. It's only a starting point in the form -
// a deployment behind a reverse proxy terminating TLS may need to adjust
// it, since this server has no way to know its own externally-visible
// scheme otherwise.
func suggestedRedirectURI(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" {
		scheme = "http"
	}
	return scheme + "://" + r.Host + "/login/oidc/callback"
}
