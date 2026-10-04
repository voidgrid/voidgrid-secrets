package model

import (
	"errors"
	"time"
)

// ErrAccountDisabled is returned when a disabled account tries to sign in
// through a path that would otherwise create a session for it.
var ErrAccountDisabled = errors.New("account disabled")

// AuthMethod identifies how a user (or the whole deployment, for
// AuthConfig) authenticates: a local password + required TOTP, or an
// external OIDC provider.
type AuthMethod string

const (
	AuthPasswordTOTP AuthMethod = "password_totp"
	AuthOIDC         AuthMethod = "oidc"
)

// User is a human account.
type User struct {
	ID         int64
	Username   string
	AuthMethod AuthMethod
	Disabled   bool
	// IsAdmin grants access to the /api/v1/admin/* routes (user, group, and
	// machine-token management). The first account created by the setup
	// wizard is always an admin; additional admins are promoted by an
	// existing one.
	IsAdmin   bool
	CreatedAt time.Time
}

// UserAuthRecord carries the extra fields needed to authenticate a user
// (password hash, decrypted TOTP secret) alongside their public fields. It
// is only ever handled by the auth/session login flow, never returned from
// general user-lookup APIs.
type UserAuthRecord struct {
	User
	PasswordHash string
	// TOTPSecret is the decrypted TOTP secret, or "" if the user hasn't
	// completed TOTP enrollment yet.
	TOTPSecret string
}

// AuthConfig records the deployment-wide authentication method chosen by
// the first-run setup wizard. Its presence in storage is what marks setup
// as complete.
type AuthConfig struct {
	AuthMethod   AuthMethod
	OIDCIssuer   string
	OIDCClientID string
	// OIDCClientSecret is the decrypted client secret, or "" when
	// AuthMethod is not AuthOIDC.
	OIDCClientSecret string
	// OIDCRedirectURI is the exact callback URL registered with the
	// provider, or "" when AuthMethod is not AuthOIDC.
	OIDCRedirectURI string
	CompletedAt     time.Time
}
