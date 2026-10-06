package api

import (
	"context"
	"errors"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/recovery"
)

// RecoverHandler resets the account through the API: the same flow as the
// web /recover pages.
type RecoverHandler struct {
	svc *recovery.Service
}

// NewRecoverHandler returns a RecoverHandler backed by svc.
func NewRecoverHandler(svc *recovery.Service) *RecoverHandler {
	return &RecoverHandler{svc: svc}
}

// RegisterRecover registers the recovery operations on api. They need no
// authentication: the code is the credential.
func RegisterRecover(api huma.API, h *RecoverHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "recover-start", Method: "POST", Path: "/recover",
		Summary: "Start an account reset with a recovery code or a break-glass code",
		Description: "Returns a reset token and, for a password account, the new TOTP secret to enroll. " +
			"Finish with recover-complete within the expiry. The code is used up either way.",
		Tags: []string{"recover"},
	}, h.Start)
	huma.Register(api, huma.Operation{
		OperationID: "recover-complete", Method: "POST", Path: "/recover/complete",
		Summary: "Finish an account reset: new password and TOTP, fresh recovery codes, every session signed out",
		Tags:    []string{"recover"},
	}, h.Complete)
}

// RecoverStartInput carries the code.
type RecoverStartInput struct {
	Body struct {
		Code string `json:"code" minLength:"1" doc:"A recovery code, or a break-glass code from 'voidgrid-secrets recover'"`
	}
}

// RecoverStartOutput is a started reset.
type RecoverStartOutput struct {
	Body struct {
		ResetToken      string    `json:"reset_token"`
		AuthMethod      string    `json:"auth_method"`
		TOTPSecret      string    `json:"totp_secret,omitempty"`
		ProvisioningURI string    `json:"provisioning_uri,omitempty"`
		ExpiresAt       time.Time `json:"expires_at"`
	}
}

// Start begins a reset.
func (h *RecoverHandler) Start(ctx context.Context, in *RecoverStartInput) (*RecoverStartOutput, error) {
	started, err := h.svc.Start(ctx, in.Body.Code)
	switch {
	case err == nil:
	case errors.Is(err, session.ErrTooManyAttempts):
		return nil, huma.Error429TooManyRequests("too many wrong codes, try again later")
	case errors.Is(err, recovery.ErrInvalidCode):
		return nil, huma.Error401Unauthorized("invalid or already used code")
	default:
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	out := &RecoverStartOutput{}
	out.Body.ResetToken = started.ResetToken
	out.Body.AuthMethod = string(started.AuthMethod)
	out.Body.TOTPSecret = started.TOTPSecret
	out.Body.ProvisioningURI = started.ProvisioningURI
	out.Body.ExpiresAt = started.ExpiresAt
	return out, nil
}

// RecoverCompleteInput finishes a reset.
type RecoverCompleteInput struct {
	Body struct {
		ResetToken  string `json:"reset_token" minLength:"1"`
		NewPassword string `json:"new_password,omitempty" doc:"Password accounts: the new password (14+ characters)"`
		TOTPCode    string `json:"totp_code,omitempty" doc:"Password accounts: a current code from the new authenticator"`
	}
}

// RecoverCompleteOutput carries the new recovery codes, shown only here.
type RecoverCompleteOutput struct {
	Body struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
}

// Complete finishes a reset.
func (h *RecoverHandler) Complete(ctx context.Context, in *RecoverCompleteInput) (*RecoverCompleteOutput, error) {
	codes, err := h.svc.Complete(ctx, in.Body.ResetToken, in.Body.NewPassword, in.Body.TOTPCode)
	switch {
	case err == nil:
	case errors.Is(err, recovery.ErrInvalidReset):
		return nil, huma.Error401Unauthorized(err.Error())
	case errors.Is(err, recovery.ErrWeakPassword), errors.Is(err, recovery.ErrInvalidTOTP):
		return nil, huma.Error400BadRequest(err.Error())
	default:
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	out := &RecoverCompleteOutput{}
	out.Body.RecoveryCodes = codes
	return out, nil
}
