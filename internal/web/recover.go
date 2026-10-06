package web

import (
	"errors"
	"net/http"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/totp"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/recovery"
)

// resetCookie holds the reset token between starting and finishing an
// account reset.
const resetCookie = "vgs_reset"

// RecoverHandler serves the account reset pages.
type RecoverHandler struct {
	svc *recovery.Service
}

// NewRecoverHandler returns a RecoverHandler backed by svc.
func NewRecoverHandler(svc *recovery.Service) *RecoverHandler {
	return &RecoverHandler{svc: svc}
}

type recoverResetPage struct {
	basePage
	AuthMethod      model.AuthMethod
	TOTPSecret      string
	ProvisioningURI string
	QRCodeDataURI   string
}

// ShowStart asks for a recovery or break-glass code.
func (h *RecoverHandler) ShowStart(w http.ResponseWriter, _ *http.Request) {
	render(w, http.StatusOK, "recover", basePage{})
}

// SubmitStart begins a reset and moves to the reset page.
func (h *RecoverHandler) SubmitStart(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	started, err := h.svc.Start(r.Context(), r.FormValue("code"))
	switch {
	case err == nil:
	case errors.Is(err, session.ErrTooManyAttempts):
		render(w, http.StatusTooManyRequests, "recover", basePage{Error: tooManyAttemptsMessage})
		return
	case errors.Is(err, recovery.ErrInvalidCode):
		render(w, http.StatusUnauthorized, "recover", basePage{Error: "that code isn't valid, or has already been used"})
		return
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: resetCookie, Value: started.ResetToken, Path: "/recover",
		Expires: started.ExpiresAt, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/recover/reset", http.StatusSeeOther)
}

// ShowReset shows the reset form: a new password and authenticator for a
// password account, a confirmation for an OIDC one.
func (h *RecoverHandler) ShowReset(w http.ResponseWriter, r *http.Request) {
	h.renderReset(w, r, http.StatusOK, "")
}

func (h *RecoverHandler) renderReset(w http.ResponseWriter, r *http.Request, status int, msg string) {
	c, err := r.Cookie(resetCookie)
	if err != nil {
		http.Redirect(w, r, "/recover", http.StatusSeeOther)
		return
	}
	reset, acct, err := h.svc.Pending(r.Context(), c.Value)
	if errors.Is(err, recovery.ErrInvalidReset) {
		render(w, http.StatusUnauthorized, "recover", basePage{Error: err.Error()})
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	page := recoverResetPage{basePage: basePage{Error: msg}, AuthMethod: acct.AuthMethod}
	if acct.AuthMethod == model.AuthPasswordTOTP {
		page.TOTPSecret = reset.PendingTOTPSecret
		page.ProvisioningURI = totp.URI(acct.Username, reset.PendingTOTPSecret)
		if page.QRCodeDataURI, err = qrCodeDataURI(page.ProvisioningURI); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	render(w, status, "recover_reset", page)
}

// SubmitReset finishes the reset and shows the new recovery codes.
func (h *RecoverHandler) SubmitReset(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(resetCookie)
	if err != nil {
		http.Redirect(w, r, "/recover", http.StatusSeeOther)
		return
	}
	if err := parseForm(w, r); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	codes, err := h.svc.Complete(r.Context(), c.Value, r.FormValue("password"), r.FormValue("totp_code"))
	switch {
	case err == nil:
	case errors.Is(err, recovery.ErrWeakPassword), errors.Is(err, recovery.ErrInvalidTOTP):
		h.renderReset(w, r, http.StatusBadRequest, err.Error())
		return
	case errors.Is(err, recovery.ErrInvalidReset):
		render(w, http.StatusUnauthorized, "recover", basePage{Error: err.Error()})
		return
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: resetCookie, Value: "", Path: "/recover", Expires: time.Unix(0, 0), MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	render(w, http.StatusOK, "recovery_codes", recoveryCodesPage{Codes: codes, ContinueTo: "/login"})
}
