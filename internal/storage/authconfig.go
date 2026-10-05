package storage

import (
	"context"
	"fmt"

	"github.com/rqlite/gorqlite"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// AuthConfigRepo provides access to the singleton auth_config row, whose
// presence marks the first-run setup wizard as complete. OIDC client
// secrets are encrypted directly with the root key, for the same reason as
// TOTP secrets in users.go: a single value per deployment, no benefit to a
// per-item DEK.
type AuthConfigRepo struct {
	db      *DB
	rootKey []byte
}

// NewAuthConfigRepo returns an AuthConfigRepo that encrypts OIDC client
// secrets using rootKey.
func NewAuthConfigRepo(db *DB, rootKey []byte) *AuthConfigRepo {
	return &AuthConfigRepo{db: db, rootKey: rootKey}
}

// IsComplete reports whether the setup wizard has already run.
func (r *AuthConfigRepo) IsComplete(ctx context.Context) (bool, error) {
	qr, err := r.db.conn.QueryContext(ctx, []string{"SELECT COUNT(*) FROM auth_config WHERE id = 1"})
	if err != nil {
		return false, fmt.Errorf("storage: check setup completion: %w", err)
	}
	if len(qr) == 0 || !qr[0].Next() {
		return false, fmt.Errorf("storage: check setup completion: no result")
	}
	var count int64
	if err := qr[0].Scan(&count); err != nil {
		return false, fmt.Errorf("storage: check setup completion: %w", err)
	}
	return count > 0, nil
}

// CompletePasswordTOTP marks setup as complete using the password+TOTP
// method.
func (r *AuthConfigRepo) CompletePasswordTOTP(ctx context.Context) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query:     `INSERT INTO auth_config (id, auth_method, completed_at) VALUES (1, 'password_totp', ?)`,
			Arguments: []interface{}{nowTimestamp()},
		},
	})
	if err != nil {
		return fmt.Errorf("storage: complete password+TOTP setup: %w", err)
	}
	if results[0].Err != nil {
		return fmt.Errorf("storage: complete password+TOTP setup: %w", results[0].Err)
	}
	return nil
}

// CompleteOIDC marks setup as complete using OIDC, storing the provider
// config with the client secret encrypted. redirectURI is the exact
// callback URL registered with the provider (e.g.
// "https://secrets.example.com/login/oidc/callback") - OIDC providers
// require it to match exactly, so it's stored rather than guessed later
// from a request.
func (r *AuthConfigRepo) CompleteOIDC(ctx context.Context, issuer, clientID, clientSecret, redirectURI string) error {
	ciphertext, nonce, err := crypto.Encrypt(r.rootKey, []byte(clientSecret))
	if err != nil {
		return fmt.Errorf("storage: encrypt OIDC client secret: %w", err)
	}

	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query: `INSERT INTO auth_config
				(id, auth_method, oidc_issuer, oidc_client_id, oidc_client_secret_enc, oidc_client_secret_nonce, oidc_redirect_uri, completed_at)
				VALUES (1, 'oidc', ?, ?, ?, ?, ?, ?)`,
			Arguments: []interface{}{issuer, clientID, b64enc(ciphertext), b64enc(nonce), redirectURI, nowTimestamp()},
		},
	})
	if err != nil {
		return fmt.Errorf("storage: complete OIDC setup: %w", err)
	}
	if results[0].Err != nil {
		return fmt.Errorf("storage: complete OIDC setup: %w", results[0].Err)
	}
	return nil
}

// Get returns the current auth configuration. Callers should check
// IsComplete first; Get returns an error if setup hasn't run yet.
func (r *AuthConfigRepo) Get(ctx context.Context) (model.AuthConfig, error) {
	qr, err := r.db.conn.QueryContext(ctx, []string{
		`SELECT auth_method, oidc_issuer, oidc_client_id, oidc_client_secret_enc, oidc_client_secret_nonce, oidc_redirect_uri, completed_at
			FROM auth_config WHERE id = 1`,
	})
	if err != nil {
		return model.AuthConfig{}, fmt.Errorf("storage: get auth config: %w", err)
	}
	if len(qr) == 0 || !qr[0].Next() {
		return model.AuthConfig{}, fmt.Errorf("storage: setup has not been completed yet")
	}

	var (
		cfg             model.AuthConfig
		authMethod      string
		oidcIssuer      gorqlite.NullString
		oidcClientID    gorqlite.NullString
		oidcSecretEnc   gorqlite.NullString
		oidcSecretNonce gorqlite.NullString
		oidcRedirectURI gorqlite.NullString
		completedAtRaw  string
	)
	if err := qr[0].Scan(&authMethod, &oidcIssuer, &oidcClientID, &oidcSecretEnc, &oidcSecretNonce, &oidcRedirectURI, &completedAtRaw); err != nil {
		return model.AuthConfig{}, fmt.Errorf("storage: scan auth config: %w", err)
	}
	cfg.AuthMethod = model.AuthMethod(authMethod)
	cfg.OIDCIssuer = oidcIssuer.String
	cfg.OIDCClientID = oidcClientID.String
	cfg.OIDCRedirectURI = oidcRedirectURI.String

	cfg.CompletedAt, err = parseTimestamp(completedAtRaw)
	if err != nil {
		return model.AuthConfig{}, fmt.Errorf("storage: parse completed_at: %w", err)
	}

	if oidcSecretEnc.Valid && oidcSecretNonce.Valid {
		ciphertext, err := b64dec(oidcSecretEnc.String)
		if err != nil {
			return model.AuthConfig{}, fmt.Errorf("storage: decode OIDC client secret: %w", err)
		}
		nonce, err := b64dec(oidcSecretNonce.String)
		if err != nil {
			return model.AuthConfig{}, fmt.Errorf("storage: decode OIDC client secret nonce: %w", err)
		}
		plaintext, err := crypto.Decrypt(r.rootKey, ciphertext, nonce)
		if err != nil {
			return model.AuthConfig{}, fmt.Errorf("storage: decrypt OIDC client secret: %w", err)
		}
		cfg.OIDCClientSecret = string(plaintext)
	}

	return cfg, nil
}
