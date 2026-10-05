package storage

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/rqlite/gorqlite"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// SecretRepo provides access to the secrets table, transparently applying
// envelope encryption/decryption around the configured root key.
type SecretRepo struct {
	db      *DB
	rootKey []byte
}

// NewSecretRepo returns a SecretRepo that encrypts/decrypts using rootKey.
func NewSecretRepo(db *DB, rootKey []byte) *SecretRepo {
	return &SecretRepo{db: db, rootKey: rootKey}
}

// UserCanAccess reports whether userID holds permission on secretID via
// any of: direct ownership, membership (read) or admin role (write) in the
// owning group, or an explicit share (direct or via group membership). A
// "write" grant implies "read", matching token.CanAccess's semantics for
// machine tokens.
func (r *SecretRepo) UserCanAccess(ctx context.Context, userID, secretID int64, permission string) (bool, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `SELECT EXISTS (
			SELECT 1 FROM secrets
				WHERE id = ? AND owner_type = 'user' AND owner_id = ?
			UNION
			SELECT 1 FROM secrets s JOIN user_groups ug ON ug.group_id = s.owner_id
				WHERE s.id = ? AND s.owner_type = 'group' AND ug.user_id = ?
					AND (? = 'read' OR ug.role = 'admin')
			UNION
			SELECT 1 FROM secret_shares
				WHERE secret_id = ? AND grantee_type = 'user' AND grantee_id = ?
					AND (permission = ? OR permission = 'write')
			UNION
			SELECT 1 FROM secret_shares ss JOIN user_groups ug ON ug.group_id = ss.grantee_id
				WHERE ss.secret_id = ? AND ss.grantee_type = 'group' AND ug.user_id = ?
					AND (ss.permission = ? OR ss.permission = 'write')
		)`,
		Arguments: []interface{}{
			secretID, userID,
			secretID, userID, permission,
			secretID, userID, permission,
			secretID, userID, permission,
		},
	})
	if err != nil {
		return false, fmt.Errorf("storage: check access for user %d on secret %d: %w", userID, secretID, err)
	}
	if !qr.Next() {
		return false, fmt.Errorf("storage: check access for user %d on secret %d: no result", userID, secretID)
	}
	var allowed bool
	if err := qr.Scan(&allowed); err != nil {
		return false, fmt.Errorf("storage: scan access check for user %d on secret %d: %w", userID, secretID, err)
	}
	return allowed, nil
}

// Create encrypts value under a freshly generated data-encryption key
// (itself wrapped by the root key) and inserts the resulting secret,
// returning its stored metadata.
func (r *SecretRepo) Create(ctx context.Context, ownerType model.OwnerType, ownerID int64, name string, value []byte, createdBy int64) (model.Secret, error) {
	dek, err := crypto.GenerateDEK()
	if err != nil {
		return model.Secret{}, err
	}
	wrappedDEK, dekNonce, err := crypto.WrapDEK(r.rootKey, dek)
	if err != nil {
		return model.Secret{}, err
	}
	ciphertext, valueNonce, err := crypto.Encrypt(dek, value)
	if err != nil {
		return model.Secret{}, err
	}

	now := nowTimestamp()
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query: `INSERT INTO secrets
				(name, owner_type, owner_id, wrapped_dek, dek_nonce, ciphertext, value_nonce, key_version, created_by, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`,
			Arguments: []interface{}{
				name, string(ownerType), ownerID,
				b64enc(wrappedDEK), b64enc(dekNonce), b64enc(ciphertext), b64enc(valueNonce),
				createdBy, now, now,
			},
		},
	})
	if err != nil {
		return model.Secret{}, fmt.Errorf("storage: insert secret: %w", err)
	}
	if results[0].Err != nil {
		return model.Secret{}, fmt.Errorf("storage: insert secret: %w", results[0].Err)
	}

	return r.Get(ctx, results[0].LastInsertID)
}

// Update re-encrypts a secret in place under a freshly generated DEK and
// stores the new value, satisfying the "encrypted store editable"
// requirement without needing to decrypt or touch any other secret. It
// returns the updated metadata.
func (r *SecretRepo) Update(ctx context.Context, id int64, value []byte) (model.Secret, error) {
	dek, err := crypto.GenerateDEK()
	if err != nil {
		return model.Secret{}, err
	}
	wrappedDEK, dekNonce, err := crypto.WrapDEK(r.rootKey, dek)
	if err != nil {
		return model.Secret{}, err
	}
	ciphertext, valueNonce, err := crypto.Encrypt(dek, value)
	if err != nil {
		return model.Secret{}, err
	}

	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query: `UPDATE secrets
				SET wrapped_dek = ?, dek_nonce = ?, ciphertext = ?, value_nonce = ?, updated_at = ?
				WHERE id = ?`,
			Arguments: []interface{}{
				b64enc(wrappedDEK), b64enc(dekNonce), b64enc(ciphertext), b64enc(valueNonce),
				formatTimestamp(time.Now()), id,
			},
		},
	})
	if err != nil {
		return model.Secret{}, fmt.Errorf("storage: update secret %d: %w", id, err)
	}
	if results[0].Err != nil {
		return model.Secret{}, fmt.Errorf("storage: update secret %d: %w", id, results[0].Err)
	}
	if results[0].RowsAffected == 0 {
		return model.Secret{}, fmt.Errorf("storage: secret %d not found", id)
	}

	return r.Get(ctx, id)
}

// Get returns a secret's metadata without decrypting its value.
func (r *SecretRepo) Get(ctx context.Context, id int64) (model.Secret, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `SELECT id, name, owner_type, owner_id, key_version, created_by, created_at, updated_at
			FROM secrets WHERE id = ?`,
		Arguments: []interface{}{id},
	})
	if err != nil {
		return model.Secret{}, fmt.Errorf("storage: get secret %d: %w", id, err)
	}
	if !qr.Next() {
		return model.Secret{}, fmt.Errorf("storage: secret %d not found", id)
	}

	s, err := scanSecret(qr)
	if err != nil {
		return model.Secret{}, fmt.Errorf("storage: scan secret %d: %w", id, err)
	}
	return s, nil
}

// ListForUser returns every secret userID can access: directly owned,
// owned by a group they belong to, or explicitly shared with them (either
// directly or via a group), ordered by name.
func (r *SecretRepo) ListForUser(ctx context.Context, userID int64) ([]model.Secret, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `SELECT DISTINCT s.id, s.name, s.owner_type, s.owner_id, s.key_version, s.created_by, s.created_at, s.updated_at
			FROM secrets s
			WHERE (s.owner_type = 'user' AND s.owner_id = ?)
				OR (s.owner_type = 'group' AND s.owner_id IN (SELECT group_id FROM user_groups WHERE user_id = ?))
				OR s.id IN (
					SELECT secret_id FROM secret_shares
					WHERE (grantee_type = 'user' AND grantee_id = ?)
						OR (grantee_type = 'group' AND grantee_id IN (SELECT group_id FROM user_groups WHERE user_id = ?))
				)
			ORDER BY s.name`,
		Arguments: []interface{}{userID, userID, userID, userID},
	})
	if err != nil {
		return nil, fmt.Errorf("storage: list secrets for user %d: %w", userID, err)
	}

	var secrets []model.Secret
	for qr.Next() {
		s, err := scanSecret(qr)
		if err != nil {
			return nil, fmt.Errorf("storage: scan secret while listing for user %d: %w", userID, err)
		}
		secrets = append(secrets, s)
	}
	return secrets, nil
}

func scanSecret(qr gorqlite.QueryResult) (model.Secret, error) {
	var (
		s            model.Secret
		ownerType    string
		createdAtRaw string
		updatedAtRaw string
	)
	if err := qr.Scan(&s.ID, &s.Name, &ownerType, &s.OwnerID, &s.KeyVersion, &s.CreatedBy, &createdAtRaw, &updatedAtRaw); err != nil {
		return model.Secret{}, err
	}
	s.OwnerType = model.OwnerType(ownerType)

	var err error
	s.CreatedAt, err = parseTimestamp(createdAtRaw)
	if err != nil {
		return model.Secret{}, fmt.Errorf("parse created_at: %w", err)
	}
	s.UpdatedAt, err = parseTimestamp(updatedAtRaw)
	if err != nil {
		return model.Secret{}, fmt.Errorf("parse updated_at: %w", err)
	}

	return s, nil
}

// Reveal decrypts and returns a secret's plaintext value. Callers are
// responsible for audit-logging this action; Reveal itself does not.
func (r *SecretRepo) Reveal(ctx context.Context, id int64) ([]byte, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query:     `SELECT wrapped_dek, dek_nonce, ciphertext, value_nonce FROM secrets WHERE id = ?`,
		Arguments: []interface{}{id},
	})
	if err != nil {
		return nil, fmt.Errorf("storage: reveal secret %d: %w", id, err)
	}
	if !qr.Next() {
		return nil, fmt.Errorf("storage: secret %d not found", id)
	}

	var wrappedDEKB64, dekNonceB64, ciphertextB64, valueNonceB64 string
	if err := qr.Scan(&wrappedDEKB64, &dekNonceB64, &ciphertextB64, &valueNonceB64); err != nil {
		return nil, fmt.Errorf("storage: scan secret %d: %w", id, err)
	}

	wrappedDEK, err := b64dec(wrappedDEKB64)
	if err != nil {
		return nil, fmt.Errorf("storage: decode wrapped_dek for secret %d: %w", id, err)
	}
	dekNonce, err := b64dec(dekNonceB64)
	if err != nil {
		return nil, fmt.Errorf("storage: decode dek_nonce for secret %d: %w", id, err)
	}
	ciphertext, err := b64dec(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("storage: decode ciphertext for secret %d: %w", id, err)
	}
	valueNonce, err := b64dec(valueNonceB64)
	if err != nil {
		return nil, fmt.Errorf("storage: decode value_nonce for secret %d: %w", id, err)
	}

	dek, err := crypto.UnwrapDEK(r.rootKey, wrappedDEK, dekNonce)
	if err != nil {
		return nil, fmt.Errorf("storage: unwrap DEK for secret %d: %w", id, err)
	}

	plaintext, err := crypto.Decrypt(dek, ciphertext, valueNonce)
	if err != nil {
		return nil, fmt.Errorf("storage: decrypt secret %d: %w", id, err)
	}

	return plaintext, nil
}

func b64enc(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func b64dec(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
