package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rqlite/gorqlite"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// ErrUserNotFound is returned by lookups (GetByOIDCSubject) when no
// matching user exists, so callers can distinguish "not found" from a
// real storage failure without string-matching an error message.
var ErrUserNotFound = errors.New("storage: user not found")

// UserRepo provides access to the users table. TOTP secrets are encrypted
// directly with the root key (unlike secrets.go's per-secret DEKs): each
// user has at most one TOTP secret, so there's no benefit to an extra
// wrapped-DEK layer, and it keeps the schema (and this code) simpler.
type UserRepo struct {
	db      *DB
	rootKey []byte
}

// NewUserRepo returns a UserRepo that encrypts TOTP secrets using rootKey.
func NewUserRepo(db *DB, rootKey []byte) *UserRepo {
	return &UserRepo{db: db, rootKey: rootKey}
}

// CreateWithPassword inserts a new user authenticating via password+TOTP.
// The TOTP secret is not set yet; call SetTOTPSecret once enrollment
// completes.
func (r *UserRepo) CreateWithPassword(ctx context.Context, username, passwordHash string) (model.User, error) {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query:     `INSERT INTO users (username, auth_method, password_hash, created_at) VALUES (?, 'password_totp', ?, ?)`,
			Arguments: []interface{}{username, passwordHash, nowTimestamp()},
		},
	})
	if err != nil {
		return model.User{}, fmt.Errorf("storage: create user %q: %w", username, err)
	}
	if results[0].Err != nil {
		return model.User{}, fmt.Errorf("storage: create user %q: %w", username, results[0].Err)
	}
	return r.GetByID(ctx, results[0].LastInsertID)
}

// CreateWithOIDC inserts a new user authenticating via OIDC, identified by
// their provider subject claim.
func (r *UserRepo) CreateWithOIDC(ctx context.Context, username, subject string) (model.User, error) {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query:     `INSERT INTO users (username, auth_method, oidc_subject, created_at) VALUES (?, 'oidc', ?, ?)`,
			Arguments: []interface{}{username, subject, nowTimestamp()},
		},
	})
	if err != nil {
		return model.User{}, fmt.Errorf("storage: create OIDC user %q: %w", username, err)
	}
	if results[0].Err != nil {
		return model.User{}, fmt.Errorf("storage: create OIDC user %q: %w", username, results[0].Err)
	}
	return r.GetByID(ctx, results[0].LastInsertID)
}

// GetByOIDCSubject returns the user matching an OIDC provider subject
// claim, if one exists.
func (r *UserRepo) GetByOIDCSubject(ctx context.Context, subject string) (model.User, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query:     `SELECT id, username, auth_method, disabled, is_admin, created_at FROM users WHERE oidc_subject = ?`,
		Arguments: []interface{}{subject},
	})
	if err != nil {
		return model.User{}, fmt.Errorf("storage: get user by OIDC subject: %w", err)
	}
	if !qr.Next() {
		return model.User{}, ErrUserNotFound
	}
	return scanUser(qr)
}

// GetOrCreateUser implements oidc.UserProvisioner: it finds the local user
// matching subject, or creates one just-in-time on first login (OIDC
// users aren't pre-created the way the password+TOTP wizard creates its
// first account). A disabled existing user gets model.ErrAccountDisabled
// rather than a user ID, so no session is ever created for them.
//
// If the provider's preferred_username is already taken by another local
// account, the user is created under their subject claim instead - the
// unique constraint means a matching name can never map onto (and so take
// over) the existing account, but it shouldn't make login fail either.
//
// The very first user of the deployment, regardless of auth method, is
// promoted to admin - otherwise an OIDC-only deployment could never have
// one, since OIDC setup itself only stores provider config.
func (r *UserRepo) GetOrCreateUser(ctx context.Context, subject, preferredUsername string) (userID int64, created bool, err error) {
	u, err := r.GetByOIDCSubject(ctx, subject)
	if err == nil {
		if u.Disabled {
			return 0, false, model.ErrAccountDisabled
		}
		return u.ID, false, nil
	}
	if !errors.Is(err, ErrUserNotFound) {
		return 0, false, err
	}

	username := preferredUsername
	if username == "" {
		username = subject
	}

	newUser, err := r.CreateWithOIDC(ctx, username, subject)
	if err != nil && username != subject && isUniqueUsernameViolation(err) {
		newUser, err = r.CreateWithOIDC(ctx, subject, subject)
	}
	if err != nil {
		return 0, false, err
	}

	if err := r.promoteIfFirstUser(ctx, newUser.ID); err != nil {
		return 0, false, err
	}

	return newUser.ID, true, nil
}

// promoteIfFirstUser grants admin to userID only if it is the oldest user
// row and no admin exists yet. It's a single atomic UPDATE rather than a
// count-then-promote pair, so two simultaneous first logins can't both
// end up admin (only the lower ID matches) or both miss out.
func (r *UserRepo) promoteIfFirstUser(ctx context.Context, userID int64) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query: `UPDATE users SET is_admin = 1
				WHERE id = ?
				AND id = (SELECT MIN(id) FROM users)
				AND NOT EXISTS (SELECT 1 FROM users WHERE is_admin = 1)`,
			Arguments: []interface{}{userID},
		},
	})
	if err != nil {
		return fmt.Errorf("storage: promote first user %d: %w", userID, err)
	}
	if results[0].Err != nil {
		return fmt.Errorf("storage: promote first user %d: %w", userID, results[0].Err)
	}
	return nil
}

func isUniqueUsernameViolation(err error) bool {
	return strings.Contains(err.Error(), "UNIQUE constraint failed: users.username")
}

// GetByID returns a user's public fields.
func (r *UserRepo) GetByID(ctx context.Context, id int64) (model.User, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query:     `SELECT id, username, auth_method, disabled, is_admin, created_at FROM users WHERE id = ?`,
		Arguments: []interface{}{id},
	})
	if err != nil {
		return model.User{}, fmt.Errorf("storage: get user %d: %w", id, err)
	}
	if !qr.Next() {
		return model.User{}, fmt.Errorf("storage: user %d not found", id)
	}
	return scanUser(qr)
}

// CountUsers returns the total number of users, used by the setup wizard
// to tell whether an admin account already exists.
func (r *UserRepo) CountUsers(ctx context.Context) (int64, error) {
	qr, err := r.db.conn.QueryContext(ctx, []string{"SELECT COUNT(*) FROM users"})
	if err != nil {
		return 0, fmt.Errorf("storage: count users: %w", err)
	}
	if len(qr) == 0 || !qr[0].Next() {
		return 0, fmt.Errorf("storage: count users: no result")
	}
	var count int64
	if err := qr[0].Scan(&count); err != nil {
		return 0, fmt.Errorf("storage: count users: %w", err)
	}
	return count, nil
}

// PromoteToAdmin grants userID access to the admin routes. The setup
// wizard calls this for the first account it creates.
func (r *UserRepo) PromoteToAdmin(ctx context.Context, userID int64) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query:     `UPDATE users SET is_admin = 1 WHERE id = ?`,
			Arguments: []interface{}{userID},
		},
	})
	if err != nil {
		return fmt.Errorf("storage: promote user %d to admin: %w", userID, err)
	}
	if results[0].Err != nil {
		return fmt.Errorf("storage: promote user %d to admin: %w", userID, results[0].Err)
	}
	if results[0].RowsAffected == 0 {
		return fmt.Errorf("storage: user %d not found", userID)
	}
	return nil
}

// List returns every user, for the admin user-management screen.
func (r *UserRepo) List(ctx context.Context) ([]model.User, error) {
	qr, err := r.db.conn.QueryContext(ctx, []string{
		`SELECT id, username, auth_method, disabled, is_admin, created_at FROM users ORDER BY id`,
	})
	if err != nil {
		return nil, fmt.Errorf("storage: list users: %w", err)
	}
	if len(qr) == 0 {
		return nil, fmt.Errorf("storage: list users: no result")
	}

	var users []model.User
	for qr[0].Next() {
		u, err := scanUser(qr[0])
		if err != nil {
			return nil, fmt.Errorf("storage: scan user: %w", err)
		}
		users = append(users, u)
	}
	return users, nil
}

// SetDisabled enables or disables a user's account.
func (r *UserRepo) SetDisabled(ctx context.Context, userID int64, disabled bool) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query:     `UPDATE users SET disabled = ? WHERE id = ?`,
			Arguments: []interface{}{disabled, userID},
		},
	})
	if err != nil {
		return fmt.Errorf("storage: set disabled for user %d: %w", userID, err)
	}
	if results[0].Err != nil {
		return fmt.Errorf("storage: set disabled for user %d: %w", userID, results[0].Err)
	}
	if results[0].RowsAffected == 0 {
		return fmt.Errorf("storage: user %d not found", userID)
	}
	return nil
}

// SetTOTPSecret encrypts secret with the root key and stores it against
// userID, completing TOTP enrollment.
func (r *UserRepo) SetTOTPSecret(ctx context.Context, userID int64, secret string) error {
	ciphertext, nonce, err := crypto.Encrypt(r.rootKey, []byte(secret))
	if err != nil {
		return fmt.Errorf("storage: encrypt TOTP secret for user %d: %w", userID, err)
	}

	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query:     `UPDATE users SET totp_secret_enc = ?, totp_secret_nonce = ? WHERE id = ?`,
			Arguments: []interface{}{b64enc(ciphertext), b64enc(nonce), userID},
		},
	})
	if err != nil {
		return fmt.Errorf("storage: set TOTP secret for user %d: %w", userID, err)
	}
	if results[0].Err != nil {
		return fmt.Errorf("storage: set TOTP secret for user %d: %w", userID, results[0].Err)
	}
	if results[0].RowsAffected == 0 {
		return fmt.Errorf("storage: user %d not found", userID)
	}
	return nil
}

// ConsumeTOTPCode records code as userID's most recently used TOTP code,
// rejecting it (returning ok=false) if it matches the code already on
// record. TOTP codes are valid for a window of time (pquerna/otp's
// default allows one period of skew either side, ~90s), so without this
// check, an attacker who captures a valid code in transit could replay it
// repeatedly within that window. The check-and-record happens in one
// atomic UPDATE, so concurrent login attempts with the same code can't
// race past each other.
func (r *UserRepo) ConsumeTOTPCode(ctx context.Context, userID int64, code string) (ok bool, err error) {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query: `UPDATE users SET totp_last_code = ?
				WHERE id = ? AND (totp_last_code IS NULL OR totp_last_code != ?)`,
			Arguments: []interface{}{code, userID, code},
		},
	})
	if err != nil {
		return false, fmt.Errorf("storage: consume TOTP code for user %d: %w", userID, err)
	}
	if results[0].Err != nil {
		return false, fmt.Errorf("storage: consume TOTP code for user %d: %w", userID, results[0].Err)
	}
	return results[0].RowsAffected == 1, nil
}

// GetAuthRecord returns everything needed to authenticate username via
// password+TOTP, including the decrypted TOTP secret (empty if the user
// hasn't completed enrollment).
func (r *UserRepo) GetAuthRecord(ctx context.Context, username string) (model.UserAuthRecord, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `SELECT id, username, auth_method, disabled, is_admin, created_at, password_hash, totp_secret_enc, totp_secret_nonce
			FROM users WHERE username = ?`,
		Arguments: []interface{}{username},
	})
	if err != nil {
		return model.UserAuthRecord{}, fmt.Errorf("storage: get auth record for %q: %w", username, err)
	}
	if !qr.Next() {
		return model.UserAuthRecord{}, fmt.Errorf("storage: user %q not found", username)
	}

	var (
		rec             model.UserAuthRecord
		authMethod      string
		createdAtRaw    string
		passwordHash    gorqlite.NullString
		totpSecretEnc   gorqlite.NullString
		totpSecretNonce gorqlite.NullString
	)
	if err := qr.Scan(&rec.ID, &rec.Username, &authMethod, &rec.Disabled, &rec.IsAdmin, &createdAtRaw, &passwordHash, &totpSecretEnc, &totpSecretNonce); err != nil {
		return model.UserAuthRecord{}, fmt.Errorf("storage: scan auth record for %q: %w", username, err)
	}
	rec.AuthMethod = model.AuthMethod(authMethod)
	rec.PasswordHash = passwordHash.String

	rec.CreatedAt, err = parseTimestamp(createdAtRaw)
	if err != nil {
		return model.UserAuthRecord{}, fmt.Errorf("storage: parse created_at for %q: %w", username, err)
	}

	if totpSecretEnc.Valid && totpSecretNonce.Valid {
		ciphertext, err := b64dec(totpSecretEnc.String)
		if err != nil {
			return model.UserAuthRecord{}, fmt.Errorf("storage: decode TOTP secret for %q: %w", username, err)
		}
		nonce, err := b64dec(totpSecretNonce.String)
		if err != nil {
			return model.UserAuthRecord{}, fmt.Errorf("storage: decode TOTP nonce for %q: %w", username, err)
		}
		plaintext, err := crypto.Decrypt(r.rootKey, ciphertext, nonce)
		if err != nil {
			return model.UserAuthRecord{}, fmt.Errorf("storage: decrypt TOTP secret for %q: %w", username, err)
		}
		rec.TOTPSecret = string(plaintext)
	}

	return rec, nil
}

func scanUser(qr gorqlite.QueryResult) (model.User, error) {
	var (
		u            model.User
		authMethod   string
		createdAtRaw string
	)
	if err := qr.Scan(&u.ID, &u.Username, &authMethod, &u.Disabled, &u.IsAdmin, &createdAtRaw); err != nil {
		return model.User{}, err
	}
	u.AuthMethod = model.AuthMethod(authMethod)

	var err error
	u.CreatedAt, err = parseTimestamp(createdAtRaw)
	if err != nil {
		return model.User{}, fmt.Errorf("parse created_at: %w", err)
	}
	return u, nil
}
