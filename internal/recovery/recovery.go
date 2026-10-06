// Package recovery resets the account when its owner can't sign in: a
// recovery code, or a break-glass code printed by `voidgrid-secrets
// recover` inside the container, starts a reset; finishing it sets a new
// password and TOTP device (password accounts), issues fresh recovery
// codes and signs out every session. A recovery code never signs in by
// itself.
package recovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/recoverycode"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// DefaultTTL is how long a break-glass code, and a started reset, stay
// valid.
const DefaultTTL = 15 * time.Minute

// limiterKey is the AttemptLimiter key recovery attempts share: there is
// one account, so one counter.
const limiterKey = "\x00recovery"

var (
	// ErrInvalidCode is returned for a code that is neither an unused
	// recovery code nor a live break-glass code.
	ErrInvalidCode = errors.New("recovery: invalid or already used code")
	// ErrInvalidReset is returned for an unknown, expired or finished
	// reset token.
	ErrInvalidReset = errors.New("recovery: reset expired or already finished - start again with a code")
	// ErrInvalidTOTP is returned when the code from the new TOTP device
	// doesn't match.
	ErrInvalidTOTP = errors.New("recovery: that code doesn't match the new authenticator")
	// ErrWeakPassword is returned for a new password that's too short.
	ErrWeakPassword = fmt.Errorf("recovery: password must be at least %d characters", crypto.MinPasswordLength)
)

// Service runs account resets.
type Service struct {
	Users         *storage.UserRepo
	Resets        *storage.ResetRepo
	RecoveryCodes *storage.RecoveryCodeRepo
	Sessions      interface {
		RevokeAll(ctx context.Context, userID int64) error
	}
	GenerateTOTP func(accountName string) (secret, provisioningURI string, err error)
	ValidateTOTP func(code, secret string) bool
	HashPassword func(password string) (string, error)
	// Limiter throttles wrong codes. nil means no limit.
	Limiter *session.AttemptLimiter
	Audit   audit.Logger
	// TTL defaults to DefaultTTL.
	TTL time.Duration
}

// Started is a reset in progress.
type Started struct {
	// ResetToken identifies the reset until it's finished; the web UI keeps
	// it in a cookie, API clients send it back to Complete.
	ResetToken string
	AuthMethod model.AuthMethod
	// TOTPSecret and ProvisioningURI are the new authenticator to enroll
	// (password accounts only).
	TOTPSecret      string
	ProvisioningURI string
	ExpiresAt       time.Time
}

func (s *Service) ttl() time.Duration {
	if s.TTL > 0 {
		return s.TTL
	}
	return DefaultTTL
}

// Start begins a reset with a recovery code or a break-glass code.
func (s *Service) Start(ctx context.Context, code string) (Started, error) {
	if !s.Limiter.Allow(limiterKey) {
		audit.Record(ctx, s.Audit, audit.Event{
			Actor: audit.Anonymous(), Action: audit.LoginLockedOut, ResourceType: "user",
			Details: map[string]string{"method": "recovery"},
		})
		return Started{}, session.ErrTooManyAttempts
	}
	acct, err := s.Users.AuthRecord(ctx)
	if err != nil {
		return Started{}, err
	}

	resetToken, err := crypto.GenerateOpaqueToken("vgs_reset_")
	if err != nil {
		return Started{}, err
	}
	resetHash := crypto.HashToken(resetToken)
	expiresAt := time.Now().Add(s.ttl())
	code = strings.TrimSpace(code)

	source := storage.ResetFromBreakGlass
	ok, err := s.Resets.RedeemBreakGlass(ctx, crypto.HashToken(code), resetHash, expiresAt)
	if err != nil {
		return Started{}, err
	}
	if !ok {
		source = storage.ResetFromRecoveryCode
		if ok, err = s.RecoveryCodes.Consume(ctx, acct.ID, crypto.HashToken(recoverycode.Normalize(code))); err != nil {
			return Started{}, err
		}
		if ok {
			if err := s.Resets.Start(ctx, resetHash, expiresAt); err != nil {
				return Started{}, err
			}
		}
	}
	if !ok {
		s.Limiter.Fail(limiterKey)
		audit.Record(ctx, s.Audit, audit.Event{Actor: audit.Anonymous(), Action: audit.RecoveryFailed, ResourceType: "user", ResourceID: acct.ID})
		return Started{}, ErrInvalidCode
	}
	s.Limiter.Succeed(limiterKey)

	started := Started{ResetToken: resetToken, AuthMethod: acct.AuthMethod, ExpiresAt: expiresAt}
	if acct.AuthMethod == model.AuthPasswordTOTP {
		secret, uri, err := s.GenerateTOTP(acct.Username)
		if err != nil {
			return Started{}, err
		}
		if err := s.Resets.SetPendingTOTP(ctx, resetHash, secret); err != nil {
			return Started{}, err
		}
		started.TOTPSecret, started.ProvisioningURI = secret, uri
	}
	audit.Record(ctx, s.Audit, audit.Event{
		Actor: audit.Anonymous(), Action: audit.RecoveryStarted, ResourceType: "user", ResourceID: acct.ID,
		Details: map[string]string{"source": source},
	})
	return started, nil
}

// Pending returns a live reset and the account it's for, so its page can
// be shown again (e.g. after a wrong TOTP code), or ErrInvalidReset.
func (s *Service) Pending(ctx context.Context, resetToken string) (storage.Reset, model.User, error) {
	reset, ok, err := s.Resets.Get(ctx, crypto.HashToken(resetToken))
	if err != nil {
		return storage.Reset{}, model.User{}, err
	}
	if !ok {
		return storage.Reset{}, model.User{}, ErrInvalidReset
	}
	acct, err := s.Users.Get(ctx)
	if err != nil {
		return storage.Reset{}, model.User{}, err
	}
	return reset, acct, nil
}

// Complete finishes a reset. For a password account, newPassword becomes
// the password and totpCode must come from the new authenticator shown by
// Start. It returns the new recovery codes, shown once.
func (s *Service) Complete(ctx context.Context, resetToken, newPassword, totpCode string) ([]string, error) {
	reset, acct, err := s.Pending(ctx, resetToken)
	if err != nil {
		return nil, err
	}
	method := acct.AuthMethod
	var passwordHash string
	if method == model.AuthPasswordTOTP {
		if len(newPassword) < crypto.MinPasswordLength {
			return nil, ErrWeakPassword
		}
		if reset.PendingTOTPSecret == "" || !s.ValidateTOTP(totpCode, reset.PendingTOTPSecret) {
			return nil, ErrInvalidTOTP
		}
		if passwordHash, err = s.HashPassword(newPassword); err != nil {
			return nil, err
		}
	}

	// Mark the reset used before changing anything, so it can't be
	// finished twice.
	finished, err := s.Resets.Finish(ctx, crypto.HashToken(resetToken))
	if err != nil {
		return nil, err
	}
	if !finished {
		return nil, ErrInvalidReset
	}

	if method == model.AuthPasswordTOTP {
		if err := s.Users.SetPassword(ctx, passwordHash); err != nil {
			return nil, err
		}
		if err := s.Users.SetTOTPSecret(ctx, reset.PendingTOTPSecret); err != nil {
			return nil, err
		}
	}
	codes, err := s.issueRecoveryCodes(ctx, acct.ID)
	if err != nil {
		return nil, err
	}
	if err := s.Sessions.RevokeAll(ctx, acct.ID); err != nil {
		return nil, err
	}
	audit.Record(ctx, s.Audit, audit.Event{
		Actor: audit.User(acct.ID), Action: audit.RecoveryCompleted, ResourceType: "user", ResourceID: acct.ID,
		Details: map[string]string{"source": reset.Source},
	})
	return codes, nil
}

// IssueBreakGlass creates a break-glass code for the `recover` command:
// valid once, for TTL.
func (s *Service) IssueBreakGlass(ctx context.Context) (code string, expiresAt time.Time, err error) {
	if _, err := s.Users.AuthRecord(ctx); err != nil {
		return "", time.Time{}, err
	}
	if code, err = crypto.GenerateOpaqueToken("vgs_recover_"); err != nil {
		return "", time.Time{}, err
	}
	expiresAt = time.Now().Add(s.ttl())
	if err := s.Resets.IssueBreakGlass(ctx, crypto.HashToken(code), expiresAt); err != nil {
		return "", time.Time{}, err
	}
	audit.Record(ctx, s.Audit, audit.Event{Actor: audit.System(), Action: audit.BreakGlassIssued, ResourceType: "user", ResourceID: storage.AccountID})
	return code, expiresAt, nil
}

func (s *Service) issueRecoveryCodes(ctx context.Context, userID int64) ([]string, error) {
	codes, err := recoverycode.Generate()
	if err != nil {
		return nil, err
	}
	hashed := make([]string, len(codes))
	for i, c := range codes {
		hashed[i] = crypto.HashToken(c)
	}
	if err := s.RecoveryCodes.ReplaceForUser(ctx, userID, hashed); err != nil {
		return nil, err
	}
	return codes, nil
}
