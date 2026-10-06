package storage

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
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

// Encryption formats of a secret row (its aad_version column).
const (
	// aadNone: key and value encrypted without associated data - rows
	// written before migration 0007. Only UpgradeEncryption reads these.
	aadNone = 0
	// aadSecretID: the wrapped key and the value are both bound to the
	// secret's id, so neither can be moved onto another row and still
	// decrypt there. Without this, someone able to write to the database
	// (but without the root key) could copy one secret's encrypted columns
	// onto another, and a token granted the second would read the first.
	aadSecretID = 1
)

// aadUpgradeMarker is recorded in schema_migrations once every aadNone
// row has been re-encrypted, so the upgrade runs exactly once: an aadNone
// row appearing after that is refused rather than upgraded, or anyone
// with database write access could plant a swapped row and have it
// laundered into the new format.
const aadUpgradeMarker = "secret-aad-upgrade"

func secretAD(id int64, part string) []byte {
	return []byte("voidgrid-secrets/secret/" + strconv.FormatInt(id, 10) + "/" + part)
}

// sealed is a secret value encrypted for one row, base64-encoded for
// storage.
type sealed struct {
	wrappedDEK, dekNonce, ciphertext, valueNonce string
}

// seal encrypts value for secret id under a freshly generated DEK, itself
// wrapped by the root key, both bound to id.
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

// Create encrypts value under a freshly generated data-encryption key
// (itself wrapped by the root key) and inserts the resulting secret,
// returning its stored metadata. The encryption is bound to the secret's
// id, which only exists once the row does, so the row is inserted first
// with empty encrypted columns and filled in straight after; if that
// fails, the row is removed again.
func (r *SecretRepo) Create(ctx context.Context, ownerType model.OwnerType, ownerID int64, name string, value []byte, createdBy int64) (model.Secret, error) {
	now := nowTimestamp()
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query: `INSERT INTO secrets
				(name, owner_type, owner_id, wrapped_dek, dek_nonce, ciphertext, value_nonce, key_version, aad_version, created_by, created_at, updated_at)
				VALUES (?, ?, ?, '', '', '', '', 1, ?, ?, ?, ?)`,
			Arguments: []interface{}{name, string(ownerType), ownerID, aadSecretID, createdBy, now, now},
		},
	})
	if err != nil {
		return model.Secret{}, fmt.Errorf("storage: insert secret: %w", err)
	}
	if results[0].Err != nil {
		return model.Secret{}, fmt.Errorf("storage: insert secret: %w", results[0].Err)
	}
	id := results[0].LastInsertID

	if err := r.fill(ctx, id, value); err != nil {
		_, _ = r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
			{Query: `DELETE FROM secrets WHERE id = ?`, Arguments: []interface{}{id}},
		})
		return model.Secret{}, err
	}
	return r.Get(ctx, id)
}

// fill writes the encrypted value of a just-inserted secret.
func (r *SecretRepo) fill(ctx context.Context, id int64, value []byte) error {
	sv, err := r.seal(id, value)
	if err != nil {
		return err
	}
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query:     `UPDATE secrets SET wrapped_dek = ?, dek_nonce = ?, ciphertext = ?, value_nonce = ? WHERE id = ?`,
			Arguments: []interface{}{sv.wrappedDEK, sv.dekNonce, sv.ciphertext, sv.valueNonce, id},
		},
	})
	if err != nil {
		return fmt.Errorf("storage: write new secret %d: %w", id, err)
	}
	if results[0].Err != nil {
		return fmt.Errorf("storage: write new secret %d: %w", id, results[0].Err)
	}
	return nil
}

// Update re-encrypts a secret in place under a freshly generated DEK and
// stores the new value, satisfying the "encrypted store editable"
// requirement without needing to decrypt or touch any other secret. It
// returns the updated metadata.
func (r *SecretRepo) Update(ctx context.Context, id int64, value []byte) (model.Secret, error) {
	sv, err := r.seal(id, value)
	if err != nil {
		return model.Secret{}, err
	}

	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query: `UPDATE secrets
				SET wrapped_dek = ?, dek_nonce = ?, ciphertext = ?, value_nonce = ?, aad_version = ?, updated_at = ?
				WHERE id = ?`,
			Arguments: []interface{}{
				sv.wrappedDEK, sv.dekNonce, sv.ciphertext, sv.valueNonce, aadSecretID,
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

// UpgradeEncryption re-encrypts every secret written before migration
// 0007 so its key and value are bound to its id, then records that it has
// run; on every later start it does nothing. It returns how many secrets
// it re-encrypted. Values and updated_at are unchanged.
func (r *SecretRepo) UpgradeEncryption(ctx context.Context) (int, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query:     `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`,
		Arguments: []interface{}{aadUpgradeMarker},
	})
	if err != nil {
		return 0, fmt.Errorf("storage: check encryption upgrade: %w", err)
	}
	var done int64
	if !qr.Next() || qr.Scan(&done) != nil {
		return 0, fmt.Errorf("storage: check encryption upgrade: no result")
	}
	if done > 0 {
		return 0, nil
	}

	rows, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query:     `SELECT id, wrapped_dek, dek_nonce, ciphertext, value_nonce FROM secrets WHERE aad_version = ?`,
		Arguments: []interface{}{aadNone},
	})
	if err != nil {
		return 0, fmt.Errorf("storage: list secrets to upgrade: %w", err)
	}
	type legacy struct {
		id  int64
		enc sealed
	}
	var todo []legacy
	for rows.Next() {
		var l legacy
		if err := rows.Scan(&l.id, &l.enc.wrappedDEK, &l.enc.dekNonce, &l.enc.ciphertext, &l.enc.valueNonce); err != nil {
			return 0, fmt.Errorf("storage: scan secret to upgrade: %w", err)
		}
		todo = append(todo, l)
	}

	for _, l := range todo {
		value, err := r.open(l.id, l.enc, aadNone)
		if err != nil {
			return 0, err
		}
		sv, err := r.seal(l.id, value)
		if err != nil {
			return 0, err
		}
		results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
			{
				Query: `UPDATE secrets
					SET wrapped_dek = ?, dek_nonce = ?, ciphertext = ?, value_nonce = ?, aad_version = ?
					WHERE id = ? AND aad_version = ?`,
				Arguments: []interface{}{sv.wrappedDEK, sv.dekNonce, sv.ciphertext, sv.valueNonce, aadSecretID, l.id, aadNone},
			},
		})
		if err != nil {
			return 0, fmt.Errorf("storage: upgrade secret %d: %w", l.id, err)
		}
		if results[0].Err != nil {
			return 0, fmt.Errorf("storage: upgrade secret %d: %w", l.id, results[0].Err)
		}
	}

	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{Query: `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, Arguments: []interface{}{aadUpgradeMarker, nowTimestamp()}},
	})
	if err != nil {
		return 0, fmt.Errorf("storage: record encryption upgrade: %w", err)
	}
	if results[0].Err != nil {
		return 0, fmt.Errorf("storage: record encryption upgrade: %w", results[0].Err)
	}
	return len(todo), nil
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
		Query:     `SELECT wrapped_dek, dek_nonce, ciphertext, value_nonce, aad_version FROM secrets WHERE id = ?`,
		Arguments: []interface{}{id},
	})
	if err != nil {
		return nil, fmt.Errorf("storage: reveal secret %d: %w", id, err)
	}
	if !qr.Next() {
		return nil, fmt.Errorf("storage: secret %d not found", id)
	}

	var (
		enc        sealed
		aadVersion int64
	)
	if err := qr.Scan(&enc.wrappedDEK, &enc.dekNonce, &enc.ciphertext, &enc.valueNonce, &aadVersion); err != nil {
		return nil, fmt.Errorf("storage: scan secret %d: %w", id, err)
	}
	if aadVersion != aadSecretID {
		return nil, fmt.Errorf("storage: secret %d is in an unsupported encryption format (aad_version %d)", id, aadVersion)
	}
	return r.open(id, enc, aadSecretID)
}

// open decrypts enc, the encrypted columns of secret id, in the given
// format.
func (r *SecretRepo) open(id int64, enc sealed, aadVersion int) ([]byte, error) {
	wrappedDEK, err := b64dec(enc.wrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("storage: decode wrapped_dek for secret %d: %w", id, err)
	}
	dekNonce, err := b64dec(enc.dekNonce)
	if err != nil {
		return nil, fmt.Errorf("storage: decode dek_nonce for secret %d: %w", id, err)
	}
	ciphertext, err := b64dec(enc.ciphertext)
	if err != nil {
		return nil, fmt.Errorf("storage: decode ciphertext for secret %d: %w", id, err)
	}
	valueNonce, err := b64dec(enc.valueNonce)
	if err != nil {
		return nil, fmt.Errorf("storage: decode value_nonce for secret %d: %w", id, err)
	}

	var dekAD, valueAD []byte
	if aadVersion == aadSecretID {
		dekAD, valueAD = secretAD(id, "dek"), secretAD(id, "value")
	}
	dek, err := crypto.UnwrapDEKWithAD(r.rootKey, wrappedDEK, dekNonce, dekAD)
	if err != nil {
		return nil, fmt.Errorf("storage: unwrap DEK for secret %d: %w", id, err)
	}
	plaintext, err := crypto.DecryptWithAD(dek, ciphertext, valueNonce, valueAD)
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
