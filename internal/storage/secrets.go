package storage

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rqlite/gorqlite"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// ErrSecretNotFound is returned when a secret id doesn't exist.
var ErrSecretNotFound = errors.New("storage: secret not found")

// ErrSecretNameTaken is returned when creating or renaming a secret to a
// name another secret already has.
var ErrSecretNameTaken = errors.New("storage: a secret with that name already exists")

// SecretRepo stores secrets encrypted: each value under its own random
// data-encryption key (DEK), which is itself wrapped by the root key. Both
// the wrapped DEK and the value are bound to the secret's id as associated
// data, so encrypted columns copied onto another row don't decrypt there -
// a token granted one secret can't be made to read another.
type SecretRepo struct {
	db      *DB
	rootKey []byte
}

// NewSecretRepo returns a SecretRepo that wraps DEKs with rootKey.
func NewSecretRepo(db *DB, rootKey []byte) *SecretRepo {
	return &SecretRepo{db: db, rootKey: rootKey}
}

func secretAD(id int64, part string) []byte {
	return []byte("voidgrid-secrets/secret/" + strconv.FormatInt(id, 10) + "/" + part)
}

// sealed is a secret value encrypted for one row, base64-encoded.
type sealed struct {
	wrappedDEK, dekNonce, ciphertext, valueNonce string
}

func (r *SecretRepo) seal(id int64, value []byte) (sealed, error) {
	dek, err := crypto.GenerateDEK()
	if err != nil {
		return sealed{}, err
	}
	wrappedDEK, dekNonce, err := crypto.WrapDEKWithAD(r.rootKey, dek, secretAD(id, "dek"))
	if err != nil {
		return sealed{}, err
	}
	ciphertext, valueNonce, err := crypto.EncryptWithAD(dek, value, secretAD(id, "value"))
	if err != nil {
		return sealed{}, err
	}
	return sealed{b64enc(wrappedDEK), b64enc(dekNonce), b64enc(ciphertext), b64enc(valueNonce)}, nil
}

func (r *SecretRepo) open(id int64, enc sealed) ([]byte, error) {
	var parts [4][]byte
	for i, s := range []string{enc.wrappedDEK, enc.dekNonce, enc.ciphertext, enc.valueNonce} {
		b, err := b64dec(s)
		if err != nil {
			return nil, fmt.Errorf("storage: decode secret %d: %w", id, err)
		}
		parts[i] = b
	}
	dek, err := crypto.UnwrapDEKWithAD(r.rootKey, parts[0], parts[1], secretAD(id, "dek"))
	if err != nil {
		return nil, fmt.Errorf("storage: unwrap DEK for secret %d: %w", id, err)
	}
	plaintext, err := crypto.DecryptWithAD(dek, parts[2], parts[3], secretAD(id, "value"))
	if err != nil {
		return nil, fmt.Errorf("storage: decrypt secret %d: %w", id, err)
	}
	return plaintext, nil
}

// Create stores a new secret. The encryption is bound to the secret's id,
// which only exists once the row does, so the row is inserted with empty
// encrypted columns and filled in straight after; if that fails, the row
// is removed again.
func (r *SecretRepo) Create(ctx context.Context, name string, value []byte) (model.Secret, error) {
	now := nowTimestamp()
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{
		Query: `INSERT INTO secrets (name, wrapped_dek, dek_nonce, ciphertext, value_nonce, created_at, updated_at)
			VALUES (?, '', '', '', '', ?, ?)`,
		Arguments: []interface{}{name, now, now},
	}})
	if err := writeErr("create secret", results, err); err != nil {
		if isUniqueNameViolation(err) {
			return model.Secret{}, ErrSecretNameTaken
		}
		return model.Secret{}, err
	}
	id := results[0].LastInsertID

	if err := r.store(ctx, id, value, ""); err != nil {
		_, _ = r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
			{Query: `DELETE FROM secrets WHERE id = ?`, Arguments: []interface{}{id}},
		})
		return model.Secret{}, err
	}
	return r.Get(ctx, id)
}

// Update re-encrypts a secret under a fresh DEK with a new value.
func (r *SecretRepo) Update(ctx context.Context, id int64, value []byte) (model.Secret, error) {
	if err := r.store(ctx, id, value, nowTimestamp()); err != nil {
		return model.Secret{}, err
	}
	return r.Get(ctx, id)
}

// store writes value into secret id; a non-empty updatedAt also bumps
// updated_at (a new value), while a just-created secret keeps its own.
func (r *SecretRepo) store(ctx context.Context, id int64, value []byte, updatedAt string) error {
	sv, err := r.seal(id, value)
	if err != nil {
		return err
	}
	query := `UPDATE secrets SET wrapped_dek = ?, dek_nonce = ?, ciphertext = ?, value_nonce = ? WHERE id = ?`
	args := []interface{}{sv.wrappedDEK, sv.dekNonce, sv.ciphertext, sv.valueNonce, id}
	if updatedAt != "" {
		query = `UPDATE secrets SET wrapped_dek = ?, dek_nonce = ?, ciphertext = ?, value_nonce = ?, updated_at = ? WHERE id = ?`
		args = []interface{}{sv.wrappedDEK, sv.dekNonce, sv.ciphertext, sv.valueNonce, updatedAt, id}
	}
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{Query: query, Arguments: args}})
	if err := writeErr("write secret", results, err); err != nil {
		return err
	}
	if results[0].RowsAffected == 0 {
		return ErrSecretNotFound
	}
	return nil
}

// Rename changes a secret's name. Its encryption is bound to its id, not
// its name, so nothing is re-encrypted. Token grants that derive their
// environment variable name from the secret's name follow the new name.
func (r *SecretRepo) Rename(ctx context.Context, id int64, name string) (model.Secret, error) {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{
		Query:     `UPDATE secrets SET name = ?, updated_at = ? WHERE id = ?`,
		Arguments: []interface{}{name, nowTimestamp(), id},
	}})
	if err := writeErr("rename secret", results, err); err != nil {
		if isUniqueNameViolation(err) {
			return model.Secret{}, ErrSecretNameTaken
		}
		return model.Secret{}, err
	}
	if results[0].RowsAffected == 0 {
		return model.Secret{}, ErrSecretNotFound
	}
	return r.Get(ctx, id)
}

// Delete removes a secret. Token grants on it go with it (foreign key
// cascade).
func (r *SecretRepo) Delete(ctx context.Context, id int64) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{
		Query: `DELETE FROM secrets WHERE id = ?`, Arguments: []interface{}{id},
	}})
	if err := writeErr("delete secret", results, err); err != nil {
		return err
	}
	if results[0].RowsAffected == 0 {
		return ErrSecretNotFound
	}
	return nil
}

// Get returns a secret's metadata without decrypting its value.
func (r *SecretRepo) Get(ctx context.Context, id int64) (model.Secret, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query:     `SELECT id, name, key_version, created_at, updated_at FROM secrets WHERE id = ?`,
		Arguments: []interface{}{id},
	})
	if err != nil {
		return model.Secret{}, fmt.Errorf("storage: get secret %d: %w", id, err)
	}
	if !qr.Next() {
		return model.Secret{}, ErrSecretNotFound
	}
	return scanSecret(qr)
}

// List returns every secret's metadata, ordered by name.
func (r *SecretRepo) List(ctx context.Context) ([]model.Secret, error) {
	qr, err := r.db.conn.QueryOneContext(ctx, `SELECT id, name, key_version, created_at, updated_at FROM secrets ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("storage: list secrets: %w", err)
	}
	secrets := []model.Secret{}
	for qr.Next() {
		s, err := scanSecret(qr)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, s)
	}
	return secrets, nil
}

// Reveal decrypts and returns a secret's value. Callers audit it.
func (r *SecretRepo) Reveal(ctx context.Context, id int64) ([]byte, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query:     `SELECT wrapped_dek, dek_nonce, ciphertext, value_nonce FROM secrets WHERE id = ?`,
		Arguments: []interface{}{id},
	})
	if err != nil {
		return nil, fmt.Errorf("storage: reveal secret %d: %w", id, err)
	}
	if !qr.Next() {
		return nil, ErrSecretNotFound
	}
	var enc sealed
	if err := qr.Scan(&enc.wrappedDEK, &enc.dekNonce, &enc.ciphertext, &enc.valueNonce); err != nil {
		return nil, fmt.Errorf("storage: scan secret %d: %w", id, err)
	}
	return r.open(id, enc)
}

func scanSecret(qr gorqlite.QueryResult) (model.Secret, error) {
	var (
		s                  model.Secret
		createdRaw, updRaw string
	)
	if err := qr.Scan(&s.ID, &s.Name, &s.KeyVersion, &createdRaw, &updRaw); err != nil {
		return model.Secret{}, fmt.Errorf("storage: scan secret: %w", err)
	}
	var err error
	if s.CreatedAt, err = parseTimestamp(createdRaw); err != nil {
		return model.Secret{}, fmt.Errorf("storage: parse created_at: %w", err)
	}
	if s.UpdatedAt, err = parseTimestamp(updRaw); err != nil {
		return model.Secret{}, fmt.Errorf("storage: parse updated_at: %w", err)
	}
	return s, nil
}

// writeErr folds a gorqlite write's two error channels into one.
func writeErr(what string, results []gorqlite.WriteResult, err error) error {
	if err != nil {
		return fmt.Errorf("storage: %s: %w", what, err)
	}
	if len(results) > 0 && results[0].Err != nil {
		return fmt.Errorf("storage: %s: %w", what, results[0].Err)
	}
	return nil
}

func isUniqueNameViolation(err error) bool {
	return strings.Contains(err.Error(), "UNIQUE constraint failed: secrets.name")
}

func b64enc(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func b64dec(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// timeOrNil formats t for storage, or returns nil for a NULL column.
func timeOrNil(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return formatTimestamp(*t)
}
