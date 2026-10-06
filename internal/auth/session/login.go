package session

import (
	"context"
	"errors"
	"sync"
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

// ErrTooManyAttempts is returned instead of checking credentials at all
// once a username has had too many failed logins recently (see
// AttemptLimiter).
var ErrTooManyAttempts = errors.New("session: too many failed login attempts for this account, try again later")

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
	// Limiter throttles repeated failures per username, across both login
	// flows. nil means no limit.
	Limiter *AttemptLimiter
}

var (
	dummyHashOnce sync.Once
	dummyHash     string
)

// dummyPasswordHash is verified against when the username doesn't exist
// (or can't use password login), so those attempts take as long as a real
// one and response timing doesn't reveal which usernames exist.
func dummyPasswordHash() string {
	dummyHashOnce.Do(func() {
		dummyHash, _ = crypto.HashPassword("voidgrid-secrets dummy password, never matches")
	})
	return dummyHash
}

// limited runs a login attempt for username through s.Limiter: refused
// outright while the username is locked out, counted as a failure on
// ErrInvalidCredentials, and clearing the count on success.
func (s *LoginService) limited(username string, attempt func() (string, time.Time, error)) (string, time.Time, error) {
	if !s.Limiter.Allow(username) {
		return "", time.Time{}, ErrTooManyAttempts
	}
	plaintext, expiresAt, err := attempt()
	switch {
	case err == nil:
		s.Limiter.Succeed(username)
	case errors.Is(err, ErrInvalidCredentials):
		s.Limiter.Fail(username)
	}
	return plaintext, expiresAt, err
}

// Login authenticates username/password/totpCode and, on success, returns
// a new session token and its expiry.
func (s *LoginService) Login(ctx context.Context, username, password, totpCode string) (plaintext string, expiresAt time.Time, err error) {
	return s.limited(username, func() (string, time.Time, error) {
		return s.login(ctx, username, password, totpCode)
	})
}

func (s *LoginService) login(ctx context.Context, username, password, totpCode string) (plaintext string, expiresAt time.Time, err error) {
	rec, err := s.Users.GetAuthRecord(ctx, username)
	// OIDC-only users (or any other method), disabled accounts and users
	// without a password can't use this flow - but the password is still
	// checked, against a dummy hash, so they take as long to reject as a
	// wrong password does.
	eligible := err == nil && !rec.Disabled && rec.AuthMethod == model.AuthPasswordTOTP && rec.PasswordHash != ""
	hash := rec.PasswordHash
	if !eligible {
		hash = dummyPasswordHash()
	}

	ok, err := s.VerifyPassword(password, hash)
	if !eligible || err != nil || !ok {
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
	return s.limited(username, func() (string, time.Time, error) {
		return s.loginWithRecoveryCode(ctx, username, code)
	})
}

func (s *LoginService) loginWithRecoveryCode(ctx context.Context, username, code string) (plaintext string, expiresAt time.Time, err error) {
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
