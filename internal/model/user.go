package model

import (
	"time"
)

// AuthMethod identifies how the account (and so the deployment)
// authenticates: a local password + required TOTP, or an external OIDC
// provider.
type AuthMethod string

const (
	AuthPasswordTOTP AuthMethod = "password_totp"
	AuthOIDC         AuthMethod = "oidc"
)

// User is the one account. voidgrid-secrets is single-user: the account is
// created by the setup wizard and is the only one there will ever be.
type User struct {
	ID         int64
	Username   string
	AuthMethod AuthMethod
	CreatedAt  time.Time
}

// UserAuthRecord carries the extra fields needed to authenticate the
// account (password hash, decrypted TOTP secret) alongside its public
// fields. It is only ever handled by the sign-in flows.
type UserAuthRecord struct {
	User
	PasswordHash string
	// TOTPSecret is the decrypted TOTP secret, or "" if TOTP enrollment
	// hasn't completed yet.
	TOTPSecret string
	// OIDCSubject is the identity provider's subject for an OIDC account.
	OIDCSubject string
}

// AuthConfig records the authentication method chosen by the setup
// wizard. Setup is complete once CompletedAt is set; an OIDC deployment
// stores its config first and completes on the operator's first sign-in.
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
	// CompletedAt is nil while setup is still in progress.
	CompletedAt *time.Time
}
