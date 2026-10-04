package session

import (
	"context"
	"errors"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// ErrInvalidCredentials is returned by LoginService.Login for any failure
// in the login flow (unknown user, wrong password, missing/invalid TOTP
// code, disabled account, wrong auth method). Deliberately generic: a
// login endpoint must never reveal which specific check failed, or it
// becomes a username/enrollment oracle.
var ErrInvalidCredentials = errors.New("session: invalid username, password, or TOTP code")

// DefaultTTL is the default session lifetime.
const DefaultTTL = 24 * time.Hour

// UserLookup is the subset of user storage the login flow needs.
type UserLookup interface {
	GetAuthRecord(ctx context.Context, username string) (model.UserAuthRecord, error)
	// ConsumeTOTPCode records code as the user's most recently used TOTP
	// code, returning ok=false if it has already been used (replay).
	ConsumeTOTPCode(ctx context.Context, userID int64, code string) (ok bool, err error)
}

// SessionCreator is the subset of session storage the login flow needs.
type SessionCreator interface {
	Create(ctx context.Context, userID int64, ttl time.Duration) (plaintext string, expiresAt time.Time, err error)
}

// RecoveryCodeConsumer is the subset of recovery-code storage the
// recovery-code login flow needs.
type RecoveryCodeConsumer interface {
	Consume(ctx context.Context, userID int64, codeHash string) (ok bool, err error)
}

// LoginService implements both the password+TOTP login flow (verify
// password, then require a valid TOTP code with no bypass) and the
// recovery-code fallback shared by both auth methods: a password+TOTP
// user who lost their device, or an OIDC user when the identity provider
// is unreachable, log in the same way - username plus one single-use
// recovery code.
type LoginService struct {
	Users          UserLookup
	Sessions       SessionCreator
	RecoveryCodes  RecoveryCodeConsumer
	VerifyPassword func(password, hash string) (bool, error)
	ValidateTOTP   func(code, secret string) bool
	TTL            time.Duration
}

// Login authenticates username/password/totpCode and, on success, returns
// a new session token and its expiry.
func (s *LoginService) Login(ctx context.Context, username, password, totpCode string) (plaintext string, expiresAt time.Time, err error) {
	rec, err := s.Users.GetAuthRecord(ctx, username)
	if err != nil {
		return "", time.Time{}, ErrInvalidCredentials
	}
	if rec.Disabled {
		return "", time.Time{}, ErrInvalidCredentials
	}
	if rec.AuthMethod != model.AuthPasswordTOTP {
		// OIDC-only users (or any other method) can't use this flow.
		return "", time.Time{}, ErrInvalidCredentials
	}
	if rec.PasswordHash == "" {
		return "", time.Time{}, ErrInvalidCredentials
	}

	ok, err := s.VerifyPassword(password, rec.PasswordHash)
	if err != nil || !ok {
		return "", time.Time{}, ErrInvalidCredentials
	}

	// TOTP is required with no bypass: a user who hasn't completed
	// enrollment (empty secret) cannot log in, full stop.
	if rec.TOTPSecret == "" || !s.ValidateTOTP(totpCode, rec.TOTPSecret) {
		return "", time.Time{}, ErrInvalidCredentials
	}

	// Reject a code that's already been used once: TOTP codes stay valid
	// for a window of time (the usual ±1 period skew), so without this, a
	// code captured in transit could be replayed within that window.
	fresh, err := s.Users.ConsumeTOTPCode(ctx, rec.ID, totpCode)
	if err != nil || !fresh {
		return "", time.Time{}, ErrInvalidCredentials
	}

	ttl := s.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}

	return s.Sessions.Create(ctx, rec.ID, ttl)
}

// LoginWithRecoveryCode authenticates username/code against the user's
// stored recovery codes and, on success, returns a new session token and
// its expiry. Works identically regardless of the account's normal auth
// method (password+TOTP or OIDC) - recovery codes are the one fallback
// path shared by both, since both GetAuthRecord lookups and the codes
// themselves are keyed by user, not by auth method.
func (s *LoginService) LoginWithRecoveryCode(ctx context.Context, username, code string) (plaintext string, expiresAt time.Time, err error) {
	rec, err := s.Users.GetAuthRecord(ctx, username)
	if err != nil {
		return "", time.Time{}, ErrInvalidCredentials
	}
	if rec.Disabled {
		return "", time.Time{}, ErrInvalidCredentials
	}

	ok, err := s.RecoveryCodes.Consume(ctx, rec.ID, crypto.HashToken(code))
	if err != nil || !ok {
		return "", time.Time{}, ErrInvalidCredentials
	}

	ttl := s.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}

	return s.Sessions.Create(ctx, rec.ID, ttl)
}
