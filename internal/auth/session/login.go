package session

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
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

// LoginService implements password+TOTP sign-in: verify the password,
// then require a valid, unused TOTP code - no bypass. (Recovery codes
// don't sign in; they start an account reset - see internal/recovery.)
type LoginService struct {
	Users          UserLookup
	Sessions       SessionCreator
	VerifyPassword func(password, hash string) (bool, error)
	ValidateTOTP   func(code, secret string) bool
	TTL            time.Duration
	// Limiter throttles repeated failures per username, across both login
	// flows. nil means no limit.
	Limiter *AttemptLimiter
	// Audit records every attempt. nil records nothing.
	Audit audit.Logger
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

// attempt is the outcome of one login attempt, for the limiter and the
// audit log.
type attempt struct {
	plaintext string
	expiresAt time.Time
	// userID is the account the username belongs to, if any (0 if none).
	userID int64
	// reason says why a failed attempt failed. It's recorded in the audit
	// log (which only admins can read) but never returned to the client.
	reason string
	err    error
}

func failed(userID int64, reason string) attempt {
	return attempt{userID: userID, reason: reason, err: ErrInvalidCredentials}
}

// limited runs a login attempt for username through s.Limiter - refused
// outright while the username is locked out, counted as a failure on
// ErrInvalidCredentials, clearing the count on success - and records the
// outcome in the audit log.
func (s *LoginService) limited(ctx context.Context, username, method, okAction, failAction string, run func() attempt) (string, time.Time, error) {
	details := map[string]string{"username": truncateDetail(username), "method": method}
	if !s.Limiter.Allow(username) {
		audit.Record(ctx, s.Audit, audit.Event{Actor: audit.Anonymous(), Action: audit.LoginLockedOut, ResourceType: "user", Details: details})
		return "", time.Time{}, ErrTooManyAttempts
	}
	a := run()
	switch {
	case a.err == nil:
		s.Limiter.Succeed(username)
		audit.Record(ctx, s.Audit, audit.Event{Actor: audit.User(a.userID), Action: okAction, ResourceType: "user", ResourceID: a.userID, Details: details})
	case errors.Is(a.err, ErrInvalidCredentials):
		s.Limiter.Fail(username)
		details["reason"] = a.reason
		audit.Record(ctx, s.Audit, audit.Event{Actor: audit.Anonymous(), Action: failAction, ResourceType: "user", ResourceID: a.userID, Details: details})
	}
	return a.plaintext, a.expiresAt, a.err
}

// truncateDetail bounds a client-supplied string before it's recorded.
func truncateDetail(s string) string {
	if len(s) > 100 {
		return s[:100]
	}
	return s
}

// Login authenticates username/password/totpCode and, on success, returns
// a new session token and its expiry.
func (s *LoginService) Login(ctx context.Context, username, password, totpCode string) (plaintext string, expiresAt time.Time, err error) {
	return s.limited(ctx, username, "password", audit.Login, audit.LoginFailed, func() attempt {
		return s.login(ctx, username, password, totpCode)
	})
}

func (s *LoginService) login(ctx context.Context, username, password, totpCode string) attempt {
	rec, err := s.Users.GetAuthRecord(ctx, username)
	// OIDC-only users (or any other method), disabled accounts and users
	// without a password can't use this flow - but the password is still
	// checked, against a dummy hash, so they take as long to reject as a
	// wrong password does.
	var reason string
	switch {
	case err != nil:
		reason = "unknown user"
	case rec.AuthMethod != model.AuthPasswordTOTP:
		reason = "account uses " + string(rec.AuthMethod)
	case rec.PasswordHash == "":
		reason = "no password set"
	}
	hash := rec.PasswordHash
	if reason != "" {
		hash = dummyPasswordHash()
	}

	ok, verr := s.VerifyPassword(password, hash)
	if reason != "" {
		return failed(rec.ID, reason)
	}
	if verr != nil || !ok {
		return failed(rec.ID, "wrong password")
	}

	// TOTP is required with no bypass: a user who hasn't completed
	// enrollment (empty secret) cannot log in, full stop.
	if rec.TOTPSecret == "" {
		return failed(rec.ID, "TOTP not enrolled")
	}
	if !s.ValidateTOTP(totpCode, rec.TOTPSecret) {
		return failed(rec.ID, "wrong TOTP code")
	}

	// Reject a code that's already been used once: TOTP codes stay valid
	// for a window of time (the usual ±1 period skew), so without this, a
	// code captured in transit could be replayed within that window.
	fresh, err := s.Users.ConsumeTOTPCode(ctx, rec.ID, totpCode)
	if err != nil || !fresh {
		return failed(rec.ID, "TOTP code already used")
	}

	return s.newSession(ctx, rec.ID)
}

func (s *LoginService) newSession(ctx context.Context, userID int64) attempt {
	ttl := s.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	plaintext, expiresAt, err := s.Sessions.Create(ctx, userID, ttl)
	return attempt{plaintext: plaintext, expiresAt: expiresAt, userID: userID, err: err}
}
