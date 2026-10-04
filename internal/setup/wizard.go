// Package setup implements the first-run setup wizard: choosing between
// password+TOTP and OIDC, and gating the rest of the application behind
// completing it.
package setup

import (
	"context"
	"errors"

	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// ErrAlreadyComplete is returned when a setup operation is attempted after
// the wizard has already run.
var ErrAlreadyComplete = errors.New("setup: already completed")

// ErrAdminPending is returned by InitPasswordSetup when an admin account
// already exists but hasn't confirmed TOTP enrollment yet (setup is still
// incomplete). Call ConfirmPasswordSetup for that account rather than
// creating a second one.
var ErrAdminPending = errors.New("setup: an admin account is already pending TOTP confirmation")

// ErrInvalidCode is returned by ConfirmPasswordSetup when the supplied TOTP
// code doesn't validate against the account's enrolled secret.
var ErrInvalidCode = errors.New("setup: invalid TOTP code")

// UserStore is the subset of user storage the wizard needs.
type UserStore interface {
	CreateWithPassword(ctx context.Context, username, passwordHash string) (model.User, error)
	SetTOTPSecret(ctx context.Context, userID int64, secret string) error
	GetAuthRecord(ctx context.Context, username string) (model.UserAuthRecord, error)
	CountUsers(ctx context.Context) (int64, error)
	PromoteToAdmin(ctx context.Context, userID int64) error
}

// AuthConfigStore is the subset of auth-config storage the wizard needs.
type AuthConfigStore interface {
	IsComplete(ctx context.Context) (bool, error)
	CompletePasswordTOTP(ctx context.Context) error
	CompleteOIDC(ctx context.Context, issuer, clientID, clientSecret, redirectURI string) error
}

// RecoveryCodeStore is the subset of recovery-code storage the wizard
// needs.
type RecoveryCodeStore interface {
	ReplaceForUser(ctx context.Context, userID int64, hashedCodes []string) error
}

// Wizard orchestrates the first-run setup flow.
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
	// HashRecoveryCode hashes a single plaintext recovery code for
	// storage (see internal/crypto.HashToken).
	HashRecoveryCode func(code string) string
}

// IsComplete reports whether setup has already run.
func (w *Wizard) IsComplete(ctx context.Context) (bool, error) {
	return w.AuthConfig.IsComplete(ctx)
}

// InitPasswordSetup creates the first admin account for the password+TOTP
// method and begins TOTP enrollment, returning the secret and provisioning
// URI to show the admin (as a QR code). Setup is not yet complete after
// this call: the admin must prove possession of the secret by calling
// ConfirmPasswordSetup with a valid code.
func (w *Wizard) InitPasswordSetup(ctx context.Context, username, password string) (secret, provisioningURI string, err error) {
	complete, err := w.AuthConfig.IsComplete(ctx)
	if err != nil {
		return "", "", err
	}
	if complete {
		return "", "", ErrAlreadyComplete
	}

	n, err := w.Users.CountUsers(ctx)
	if err != nil {
		return "", "", err
	}
	if n > 0 {
		return "", "", ErrAdminPending
	}

	hash, err := w.HashPassword(password)
	if err != nil {
		return "", "", err
	}
	user, err := w.Users.CreateWithPassword(ctx, username, hash)
	if err != nil {
		return "", "", err
	}
	if err := w.Users.PromoteToAdmin(ctx, user.ID); err != nil {
		return "", "", err
	}

	secret, provisioningURI, err = w.GenerateTOTP(username)
	if err != nil {
		return "", "", err
	}
	if err := w.Users.SetTOTPSecret(ctx, user.ID, secret); err != nil {
		return "", "", err
	}

	return secret, provisioningURI, nil
}

// ConfirmPasswordSetup validates code against the pending admin account's
// enrolled TOTP secret and, if valid, marks setup as complete and issues
// a fresh batch of recovery codes - shown to the admin exactly once here,
// since only the hash is ever stored.
func (w *Wizard) ConfirmPasswordSetup(ctx context.Context, username, code string) (recoveryCodes []string, err error) {
	complete, err := w.AuthConfig.IsComplete(ctx)
	if err != nil {
		return nil, err
	}
	if complete {
		return nil, ErrAlreadyComplete
	}

	rec, err := w.Users.GetAuthRecord(ctx, username)
	if err != nil {
		return nil, err
	}
	if rec.TOTPSecret == "" {
		return nil, ErrAdminPending
	}
	if !w.ValidateTOTP(code, rec.TOTPSecret) {
		return nil, ErrInvalidCode
	}

	if err := w.AuthConfig.CompletePasswordTOTP(ctx); err != nil {
		return nil, err
	}

	codes, err := w.GenerateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	hashed := make([]string, len(codes))
	for i, c := range codes {
		hashed[i] = w.HashRecoveryCode(c)
	}
	if err := w.RecoveryCodes.ReplaceForUser(ctx, rec.ID, hashed); err != nil {
		return nil, err
	}

	return codes, nil
}

// SetupOIDC configures OIDC as the deployment's auth method and completes
// setup. Unlike password+TOTP, no user is pre-created here and no
// recovery codes are issued yet: OIDC users (including the first, who is
// promoted to admin) are provisioned just-in-time on their first
// successful login, which is the earliest point a user row - and so
// somewhere to attach recovery codes - exists.
func (w *Wizard) SetupOIDC(ctx context.Context, issuer, clientID, clientSecret, redirectURI string) error {
	complete, err := w.AuthConfig.IsComplete(ctx)
	if err != nil {
		return err
	}
	if complete {
		return ErrAlreadyComplete
	}

	return w.AuthConfig.CompleteOIDC(ctx, issuer, clientID, clientSecret, redirectURI)
}
