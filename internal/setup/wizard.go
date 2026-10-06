// Package setup implements the first-run setup wizard: it creates the one
// account, with password+TOTP or OIDC, and gates the rest of the
// application behind finishing it. Every step needs the setup token the
// server prints to its log at startup.
package setup

import (
	"context"
	"crypto/subtle"
	"errors"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// ErrAlreadyComplete is returned when a setup step is attempted after
// setup has finished.
var ErrAlreadyComplete = errors.New("setup: already completed")

// ErrInvalidCode is returned by ConfirmPasswordSetup when the TOTP code
// doesn't match the enrolled secret.
var ErrInvalidCode = errors.New("setup: invalid TOTP code")

// ErrNotStarted is returned when a later step runs before the step that
// starts it (confirming TOTP before creating the account, or claiming an
// OIDC identity before saving the OIDC config).
var ErrNotStarted = errors.New("setup: start setup from the beginning")

// ErrInvalidSetupToken is returned by every setup step when the setup
// token supplied doesn't match the one this server printed to its log at
// startup.
var ErrInvalidSetupToken = errors.New("setup: invalid setup token - use the one printed in the server log")

// UserStore is the subset of account storage the wizard needs.
type UserStore interface {
	SetupPassword(ctx context.Context, username, passwordHash string) (model.User, error)
	SetupOIDC(ctx context.Context, username, subject string) (model.User, error)
	SetTOTPSecret(ctx context.Context, secret string) error
	GetAuthRecord(ctx context.Context, username string) (model.UserAuthRecord, error)
}

// AuthConfigStore is the subset of auth-config storage the wizard needs.
type AuthConfigStore interface {
	IsComplete(ctx context.Context) (bool, error)
	CompletePasswordTOTP(ctx context.Context) error
	SaveOIDC(ctx context.Context, issuer, clientID, clientSecret, redirectURI string) error
	CompleteOIDC(ctx context.Context) error
	Get(ctx context.Context) (model.AuthConfig, error)
}

// RecoveryCodeStore is the subset of recovery-code storage the wizard
// needs.
type RecoveryCodeStore interface {
	ReplaceForUser(ctx context.Context, userID int64, hashedCodes []string) error
}

// Wizard orchestrates first-run setup.
type Wizard struct {
	Users         UserStore
	AuthConfig    AuthConfigStore
	RecoveryCodes RecoveryCodeStore
	GenerateTOTP  func(accountName string) (secret, provisioningURI string, err error)
	ValidateTOTP  func(code, secret string) bool
	HashPassword  func(password string) (string, error)
	// GenerateRecoveryCodes returns a fresh batch of plaintext recovery
	// codes (see internal/auth/recoverycode.Generate).
	GenerateRecoveryCodes func() ([]string, error)
	// HashRecoveryCode hashes one plaintext recovery code for storage
	// (see internal/crypto.HashToken).
	HashRecoveryCode func(code string) string
	// SetupToken is generated at startup while setup is incomplete and
	// printed only to the server's log, so only someone who can read that
	// log - the operator - can run setup. Every setup step requires it;
	// if it's empty, setup is refused outright.
	SetupToken string
	// Audit records setup attempts and their outcome. nil records nothing.
	Audit audit.Logger
}

// CheckSetupToken reports whether token is this server's setup token,
// recording a rejection in the audit log. Handlers call it before doing
// any other work for a setup request (OIDC setup contacts the issuer URL
// it's given), and every Wizard step checks it again.
func (w *Wizard) CheckSetupToken(ctx context.Context, token string) error {
	if w.SetupToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(w.SetupToken)) != 1 {
		audit.Record(ctx, w.Audit, audit.Event{Actor: audit.Anonymous(), Action: audit.SetupTokenRejected, ResourceType: "setup"})
		return ErrInvalidSetupToken
	}
	return nil
}

// IsComplete reports whether setup has finished.
func (w *Wizard) IsComplete(ctx context.Context) (bool, error) {
	return w.AuthConfig.IsComplete(ctx)
}

func (w *Wizard) begin(ctx context.Context, setupToken string) error {
	if err := w.CheckSetupToken(ctx, setupToken); err != nil {
		return err
	}
	complete, err := w.AuthConfig.IsComplete(ctx)
	if err != nil {
		return err
	}
	if complete {
		return ErrAlreadyComplete
	}
	return nil
}

// InitPasswordSetup creates the account for password+TOTP and begins TOTP
// enrollment, returning the secret and provisioning URI to show (as a QR
// code). Running it again before confirming replaces the account - e.g.
// if the QR code was lost. Setup completes in ConfirmPasswordSetup.
func (w *Wizard) InitPasswordSetup(ctx context.Context, setupToken, username, password string) (secret, provisioningURI string, err error) {
	if err := w.begin(ctx, setupToken); err != nil {
		return "", "", err
	}
	hash, err := w.HashPassword(password)
	if err != nil {
		return "", "", err
	}
	user, err := w.Users.SetupPassword(ctx, username, hash)
	if err != nil {
		return "", "", err
	}
	if secret, provisioningURI, err = w.GenerateTOTP(username); err != nil {
		return "", "", err
	}
	if err := w.Users.SetTOTPSecret(ctx, secret); err != nil {
		return "", "", err
	}
	audit.Record(ctx, w.Audit, audit.Event{
		Actor: audit.Anonymous(), Action: audit.SetupAccountCreated, ResourceType: "user", ResourceID: user.ID,
		Details: map[string]string{"username": username, "method": "password_totp"},
	})
	return secret, provisioningURI, nil
}

// ConfirmPasswordSetup checks code against the new account's TOTP secret
// and, if valid, completes setup and issues recovery codes - shown once
// here, since only their hashes are stored.
func (w *Wizard) ConfirmPasswordSetup(ctx context.Context, setupToken, username, code string) (recoveryCodes []string, err error) {
	if err := w.begin(ctx, setupToken); err != nil {
		return nil, err
	}
	rec, err := w.Users.GetAuthRecord(ctx, username)
	if err != nil || rec.TOTPSecret == "" {
		return nil, ErrNotStarted
	}
	if !w.ValidateTOTP(code, rec.TOTPSecret) {
		return nil, ErrInvalidCode
	}
	if err := w.AuthConfig.CompletePasswordTOTP(ctx); err != nil {
		return nil, err
	}
	codes, err := w.issueRecoveryCodes(ctx, rec.ID)
	if err != nil {
		return nil, err
	}
	audit.Record(ctx, w.Audit, audit.Event{
		Actor: audit.User(rec.ID), Action: audit.SetupCompleted, ResourceType: "setup",
		Details: map[string]string{"method": "password_totp"},
	})
	return codes, nil
}

// SetupOIDC saves the OIDC provider config. Setup isn't complete yet: it
// completes in ClaimOIDC, when the operator signs in through the provider
// and that identity becomes the account.
func (w *Wizard) SetupOIDC(ctx context.Context, setupToken, issuer, clientID, clientSecret, redirectURI string) error {
	if err := w.begin(ctx, setupToken); err != nil {
		return err
	}
	return w.AuthConfig.SaveOIDC(ctx, issuer, clientID, clientSecret, redirectURI)
}

// ClaimOIDC makes the OIDC identity (subject, preferredUsername) the
// account, completes setup, and returns the account and its recovery
// codes.
func (w *Wizard) ClaimOIDC(ctx context.Context, setupToken, subject, preferredUsername string) (model.User, []string, error) {
	if err := w.begin(ctx, setupToken); err != nil {
		return model.User{}, nil, err
	}
	cfg, err := w.AuthConfig.Get(ctx)
	if err != nil || cfg.AuthMethod != model.AuthOIDC {
		return model.User{}, nil, ErrNotStarted
	}
	user, err := w.Users.SetupOIDC(ctx, preferredUsername, subject)
	if err != nil {
		return model.User{}, nil, err
	}
	if err := w.AuthConfig.CompleteOIDC(ctx); err != nil {
		return model.User{}, nil, err
	}
	codes, err := w.issueRecoveryCodes(ctx, user.ID)
	if err != nil {
		return model.User{}, nil, err
	}
	audit.Record(ctx, w.Audit, audit.Event{
		Actor: audit.User(user.ID), Action: audit.SetupAccountCreated, ResourceType: "user", ResourceID: user.ID,
		Details: map[string]string{"username": user.Username, "method": "oidc", "subject": subject},
	})
	audit.Record(ctx, w.Audit, audit.Event{
		Actor: audit.User(user.ID), Action: audit.SetupCompleted, ResourceType: "setup",
		Details: map[string]string{"method": "oidc", "issuer": cfg.OIDCIssuer},
	})
	return user, codes, nil
}

func (w *Wizard) issueRecoveryCodes(ctx context.Context, userID int64) ([]string, error) {
	codes, err := w.GenerateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	hashed := make([]string, len(codes))
	for i, c := range codes {
		hashed[i] = w.HashRecoveryCode(c)
	}
	if err := w.RecoveryCodes.ReplaceForUser(ctx, userID, hashed); err != nil {
		return nil, err
	}
	return codes, nil
}
