package storage

import (
	"context"
	"fmt"

	"github.com/rqlite/gorqlite"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// AuthConfigRepo provides access to the singleton auth_config row. Setup
// is complete once its completed_at is set. The OIDC client secret is
// encrypted directly with the root key, for the same reason as the TOTP
// secret in users.go: a single value per deployment.
type AuthConfigRepo struct {
	db      *DB
	rootKey []byte
}

// NewAuthConfigRepo returns an AuthConfigRepo that encrypts the OIDC client
// secret using rootKey.
func NewAuthConfigRepo(db *DB, rootKey []byte) *AuthConfigRepo {
	return &AuthConfigRepo{db: db, rootKey: rootKey}
}

// IsComplete reports whether setup has finished.
func (r *AuthConfigRepo) IsComplete(ctx context.Context) (bool, error) {
	qr, err := r.db.conn.QueryOneContext(ctx, "SELECT COUNT(*) FROM auth_config WHERE id = 1 AND completed_at IS NOT NULL")
	if err != nil {
		return false, fmt.Errorf("storage: check setup completion: %w", err)
	}
	if !qr.Next() {
		return false, fmt.Errorf("storage: check setup completion: no result")
	}
	var count int64
	if err := qr.Scan(&count); err != nil {
		return false, fmt.Errorf("storage: check setup completion: %w", err)
	}
	return count > 0, nil
}

// CompletePasswordTOTP finishes setup with the password+TOTP method.
func (r *AuthConfigRepo) CompletePasswordTOTP(ctx context.Context) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{
		Query: `INSERT INTO auth_config (id, auth_method, completed_at) VALUES (1, 'password_totp', ?)
			ON CONFLICT (id) DO UPDATE SET auth_method = 'password_totp', oidc_issuer = NULL, oidc_client_id = NULL,
				oidc_client_secret_enc = NULL, oidc_client_secret_nonce = NULL, oidc_redirect_uri = NULL,
				completed_at = excluded.completed_at`,
		Arguments: []interface{}{nowTimestamp()},
	}})
	return writeErr("complete password+TOTP setup", results, err)
}

// SaveOIDC stores the OIDC provider config, client secret encrypted,
// without completing setup: that happens in CompleteOIDC, once the
// operator has signed in through the provider. redirectURI is the exact
// callback URL registered with the provider. Saving again (a corrected
// config) replaces the pending one.
func (r *AuthConfigRepo) SaveOIDC(ctx context.Context, issuer, clientID, clientSecret, redirectURI string) error {
	ciphertext, nonce, err := crypto.Encrypt(r.rootKey, []byte(clientSecret))
	if err != nil {
		return fmt.Errorf("storage: encrypt OIDC client secret: %w", err)
	}
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{
		Query: `INSERT INTO auth_config
				(id, auth_method, oidc_issuer, oidc_client_id, oidc_client_secret_enc, oidc_client_secret_nonce, oidc_redirect_uri)
				VALUES (1, 'oidc', ?, ?, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET auth_method = 'oidc', oidc_issuer = excluded.oidc_issuer,
				oidc_client_id = excluded.oidc_client_id, oidc_client_secret_enc = excluded.oidc_client_secret_enc,
				oidc_client_secret_nonce = excluded.oidc_client_secret_nonce, oidc_redirect_uri = excluded.oidc_redirect_uri,
				completed_at = NULL`,
		Arguments: []interface{}{issuer, clientID, b64enc(ciphertext), b64enc(nonce), redirectURI},
	}})
	return writeErr("save OIDC config", results, err)
}

// CompleteOIDC finishes an OIDC setup saved by SaveOIDC.
func (r *AuthConfigRepo) CompleteOIDC(ctx context.Context) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{
		Query:     `UPDATE auth_config SET completed_at = ? WHERE id = 1 AND auth_method = 'oidc' AND completed_at IS NULL`,
		Arguments: []interface{}{nowTimestamp()},
	}})
	if err := writeErr("complete OIDC setup", results, err); err != nil {
		return err
	}
	if results[0].RowsAffected == 0 {
		return fmt.Errorf("storage: complete OIDC setup: no pending OIDC config")
	}
	return nil
}

// Get returns the stored auth configuration, complete or pending, or
// ErrNotFound if setup hasn't stored any.
func (r *AuthConfigRepo) Get(ctx context.Context) (model.AuthConfig, error) {
	qr, err := r.db.conn.QueryOneContext(ctx,
		`SELECT auth_method, oidc_issuer, oidc_client_id, oidc_client_secret_enc, oidc_client_secret_nonce, oidc_redirect_uri, completed_at
			FROM auth_config WHERE id = 1`)
	if err != nil {
		return model.AuthConfig{}, fmt.Errorf("storage: get auth config: %w", err)
	}
	if !qr.Next() {
		return model.AuthConfig{}, fmt.Errorf("%w: no auth config yet", ErrNotFound)
	}

	var (
		cfg                                      model.AuthConfig
		authMethod                               string
		issuer, clientID, secretEnc, secretNonce gorqlite.NullString
		redirectURI, completedAt                 gorqlite.NullString
	)
	if err := qr.Scan(&authMethod, &issuer, &clientID, &secretEnc, &secretNonce, &redirectURI, &completedAt); err != nil {
		return model.AuthConfig{}, fmt.Errorf("storage: scan auth config: %w", err)
	}
	cfg.AuthMethod = model.AuthMethod(authMethod)
	cfg.OIDCIssuer, cfg.OIDCClientID, cfg.OIDCRedirectURI = issuer.String, clientID.String, redirectURI.String
	if cfg.CompletedAt, err = parseNullableTimestamp(completedAt.String, completedAt.Valid); err != nil {
		return model.AuthConfig{}, fmt.Errorf("storage: parse completed_at: %w", err)
	}

	if secretEnc.Valid && secretNonce.Valid {
		ciphertext, err := b64dec(secretEnc.String)
		if err != nil {
			return model.AuthConfig{}, fmt.Errorf("storage: decode OIDC client secret: %w", err)
		}
		nonce, err := b64dec(secretNonce.String)
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
