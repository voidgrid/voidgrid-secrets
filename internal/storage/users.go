package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/rqlite/gorqlite"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// AccountID is the id of the one account. The users table only ever holds
// this row (enforced by a CHECK constraint).
const AccountID int64 = 1

// ErrUserNotFound is returned when the account doesn't exist yet (setup
// hasn't created it) or a username doesn't match it.
var ErrUserNotFound = errors.New("storage: account not found")

// ErrNotOwner is returned when an OIDC identity other than the account's
// own tries to sign in.
var ErrNotOwner = errors.New("storage: this identity is not the account owner")

// ErrNotFound is returned when a write refers to a token or secret that
// doesn't exist.
var ErrNotFound = errors.New("storage: referenced token or secret not found")

// UserRepo provides access to the one account. Its TOTP secret is
// encrypted directly with the root key (unlike secrets' per-secret DEKs):
// there's only one, so an extra wrapped-key layer would buy nothing.
type UserRepo struct {
	db      *DB
	rootKey []byte
}

// NewUserRepo returns a UserRepo that encrypts TOTP secrets using rootKey.
func NewUserRepo(db *DB, rootKey []byte) *UserRepo {
	return &UserRepo{db: db, rootKey: rootKey}
}

// SetupPassword creates the account for password+TOTP sign-in, or replaces
// it while setup is still in progress (an earlier attempt whose TOTP was
// never confirmed). TOTP enrollment starts again from scratch.
func (r *UserRepo) SetupPassword(ctx context.Context, username, passwordHash string) (model.User, error) {
	if err := r.write(ctx, "set up password account",
		`INSERT INTO users (id, username, auth_method, password_hash, created_at) VALUES (?, ?, 'password_totp', ?, ?)
			ON CONFLICT (id) DO UPDATE SET username = excluded.username, auth_method = 'password_totp',
				password_hash = excluded.password_hash, totp_secret_enc = NULL, totp_secret_nonce = NULL,
				totp_last_code = NULL, oidc_subject = NULL`,
		AccountID, username, passwordHash, nowTimestamp()); err != nil {
		return model.User{}, err
	}
	return r.Get(ctx)
}

// SetupOIDC creates the account for an OIDC identity, or replaces one
// left by an unfinished setup. Only the setup wizard calls it, and only
// while setup is incomplete.
func (r *UserRepo) SetupOIDC(ctx context.Context, username, subject string) (model.User, error) {
	if username == "" {
		username = subject
	}
	if err := r.write(ctx, "set up OIDC account",
		`INSERT INTO users (id, username, auth_method, oidc_subject, created_at) VALUES (?, ?, 'oidc', ?, ?)
			ON CONFLICT (id) DO UPDATE SET username = excluded.username, auth_method = 'oidc',
				oidc_subject = excluded.oidc_subject, password_hash = NULL, totp_secret_enc = NULL,
				totp_secret_nonce = NULL, totp_last_code = NULL`,
		AccountID, username, subject, nowTimestamp()); err != nil {
		return model.User{}, err
	}
	return r.Get(ctx)
}

// OIDCOwner returns the account if subject is its OIDC identity,
// ErrNotOwner if the account belongs to a different identity (or uses a
// password), and ErrUserNotFound if there is no account yet.
func (r *UserRepo) OIDCOwner(ctx context.Context, subject string) (model.User, error) {
	rec, err := r.AuthRecord(ctx)
	if err != nil {
		return model.User{}, err
	}
	if rec.AuthMethod != model.AuthOIDC || rec.OIDCSubject != subject {
		return model.User{}, ErrNotOwner
	}
	return rec.User, nil
}

// Get returns the account, or ErrUserNotFound.
func (r *UserRepo) Get(ctx context.Context) (model.User, error) {
	rec, err := r.AuthRecord(ctx)
	return rec.User, err
}

// SetTOTPSecret encrypts secret with the root key and stores it,
// completing TOTP enrollment. The replay guard is reset with it.
func (r *UserRepo) SetTOTPSecret(ctx context.Context, secret string) error {
	ciphertext, nonce, err := crypto.Encrypt(r.rootKey, []byte(secret))
	if err != nil {
		return fmt.Errorf("storage: encrypt TOTP secret: %w", err)
	}
	return r.write(ctx, "set TOTP secret",
		`UPDATE users SET totp_secret_enc = ?, totp_secret_nonce = ?, totp_last_code = NULL WHERE id = ?`,
		b64enc(ciphertext), b64enc(nonce), AccountID)
}

// SetPassword replaces the account's password hash.
func (r *UserRepo) SetPassword(ctx context.Context, passwordHash string) error {
	return r.write(ctx, "set password", `UPDATE users SET password_hash = ? WHERE id = ?`, passwordHash, AccountID)
}

// ConsumeTOTPCode records code as the most recently used TOTP code,
// rejecting it (ok=false) if it matches the code already on record. TOTP
// codes stay valid for a window of time (one period of skew either side,
// ~90s), so without this a code captured in transit could be replayed
// within that window. The check and the record are one atomic UPDATE.
func (r *UserRepo) ConsumeTOTPCode(ctx context.Context, userID int64, code string) (ok bool, err error) {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query: `UPDATE users SET totp_last_code = ?
				WHERE id = ? AND (totp_last_code IS NULL OR totp_last_code != ?)`,
			Arguments: []interface{}{code, userID, code},
		},
	})
	if err != nil {
		return false, fmt.Errorf("storage: consume TOTP code: %w", err)
	}
	if results[0].Err != nil {
		return false, fmt.Errorf("storage: consume TOTP code: %w", results[0].Err)
	}
	return results[0].RowsAffected == 1, nil
}

// GetAuthRecord returns the account's sign-in record if username is its
// username, or ErrUserNotFound.
func (r *UserRepo) GetAuthRecord(ctx context.Context, username string) (model.UserAuthRecord, error) {
	rec, err := r.AuthRecord(ctx)
	if err != nil {
		return model.UserAuthRecord{}, err
	}
	if rec.Username != username {
		return model.UserAuthRecord{}, ErrUserNotFound
	}
	return rec, nil
}

// AuthRecord returns everything needed to authenticate the account,
// including the decrypted TOTP secret (empty before enrollment), or
// ErrUserNotFound if it doesn't exist yet.
func (r *UserRepo) AuthRecord(ctx context.Context) (model.UserAuthRecord, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `SELECT id, username, auth_method, created_at, password_hash, totp_secret_enc, totp_secret_nonce, oidc_subject
			FROM users WHERE id = ?`,
		Arguments: []interface{}{AccountID},
	})
	if err != nil {
		return model.UserAuthRecord{}, fmt.Errorf("storage: get account: %w", err)
	}
	if !qr.Next() {
		return model.UserAuthRecord{}, ErrUserNotFound
	}

	var (
		rec             model.UserAuthRecord
		authMethod      string
		createdAtRaw    string
		passwordHash    gorqlite.NullString
		totpSecretEnc   gorqlite.NullString
		totpSecretNonce gorqlite.NullString
		oidcSubject     gorqlite.NullString
	)
	if err := qr.Scan(&rec.ID, &rec.Username, &authMethod, &createdAtRaw, &passwordHash, &totpSecretEnc, &totpSecretNonce, &oidcSubject); err != nil {
		return model.UserAuthRecord{}, fmt.Errorf("storage: scan account: %w", err)
	}
	rec.AuthMethod = model.AuthMethod(authMethod)
	rec.PasswordHash = passwordHash.String
	rec.OIDCSubject = oidcSubject.String
	if rec.CreatedAt, err = parseTimestamp(createdAtRaw); err != nil {
		return model.UserAuthRecord{}, fmt.Errorf("storage: parse account created_at: %w", err)
	}

	if totpSecretEnc.Valid && totpSecretNonce.Valid {
		ciphertext, err := b64dec(totpSecretEnc.String)
		if err != nil {
			return model.UserAuthRecord{}, fmt.Errorf("storage: decode TOTP secret: %w", err)
		}
		nonce, err := b64dec(totpSecretNonce.String)
		if err != nil {
			return model.UserAuthRecord{}, fmt.Errorf("storage: decode TOTP nonce: %w", err)
		}
		plaintext, err := crypto.Decrypt(r.rootKey, ciphertext, nonce)
		if err != nil {
			return model.UserAuthRecord{}, fmt.Errorf("storage: decrypt TOTP secret: %w", err)
		}
		rec.TOTPSecret = string(plaintext)
	}
	return rec, nil
}

// write runs one parameterized statement, wrapping any error with what.
func (r *UserRepo) write(ctx context.Context, what, query string, args ...interface{}) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{Query: query, Arguments: args}})
	if err != nil {
		return fmt.Errorf("storage: %s: %w", what, err)
	}
	if results[0].Err != nil {
		return fmt.Errorf("storage: %s: %w", what, results[0].Err)
	}
	return nil
}
