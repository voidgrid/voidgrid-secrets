package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/rqlite/gorqlite"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// SessionRepo provides access to the sessions table: server-side sessions
// keyed by an opaque, hashed token, so revocation (and bulk logout) is a
// simple row update rather than requiring stateless-token tricks.
type SessionRepo struct {
	db *DB
}

// NewSessionRepo returns a SessionRepo backed by db.
func NewSessionRepo(db *DB) *SessionRepo {
	return &SessionRepo{db: db}
}

// Create generates a new session token for userID, valid for ttl, and
// returns the plaintext token (to be set as a cookie) and its expiry.
func (r *SessionRepo) Create(ctx context.Context, userID int64, ttl time.Duration) (plaintext string, expiresAt time.Time, err error) {
	plaintext, err = session.Generate()
	if err != nil {
		return "", time.Time{}, err
	}
	hash := crypto.HashToken(plaintext)
	expiresAt = time.Now().Add(ttl)

	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query:     `INSERT INTO sessions (session_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)`,
			Arguments: []interface{}{hash, userID, formatTimestamp(expiresAt), nowTimestamp()},
		},
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("storage: create session: %w", err)
	}
	if results[0].Err != nil {
		return "", time.Time{}, fmt.Errorf("storage: create session: %w", results[0].Err)
	}

	return plaintext, expiresAt, nil
}

// Authenticate validates a session token, returning the associated user.
// It returns session.ErrInvalidSession when the token is unknown, revoked,
// expired, or belongs to a disabled user.
func (r *SessionRepo) Authenticate(ctx context.Context, plaintext string) (model.User, error) {
	hash := crypto.HashToken(plaintext)

	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `SELECT s.user_id, s.expires_at, s.revoked_at, u.id, u.username, u.auth_method, u.created_at
			FROM sessions s JOIN users u ON u.id = s.user_id
			WHERE s.session_hash = ?`,
		Arguments: []interface{}{hash},
	})
	if err != nil {
		return model.User{}, fmt.Errorf("storage: authenticate session: %w", err)
	}
	if !qr.Next() {
		return model.User{}, session.ErrInvalidSession
	}

	var (
		userID       int64
		expiresAtRaw string
		revokedAt    gorqlite.NullString
		user         model.User
		authMethod   string
		createdAtRaw string
	)
	if err := qr.Scan(&userID, &expiresAtRaw, &revokedAt, &user.ID, &user.Username, &authMethod, &createdAtRaw); err != nil {
		return model.User{}, fmt.Errorf("storage: scan session: %w", err)
	}
	user.AuthMethod = model.AuthMethod(authMethod)

	if revokedAt.Valid {
		return model.User{}, session.ErrInvalidSession
	}

	expiresAt, err := parseTimestamp(expiresAtRaw)
	if err != nil {
		return model.User{}, fmt.Errorf("storage: parse session expiry: %w", err)
	}
	if expiresAt.Before(time.Now()) {
		return model.User{}, session.ErrInvalidSession
	}

	user.CreatedAt, err = parseTimestamp(createdAtRaw)
	if err != nil {
		return model.User{}, fmt.Errorf("storage: parse user created_at: %w", err)
	}

	return user, nil
}

// Revoke invalidates a session immediately, given its plaintext token (as
// presented in a logout request).
func (r *SessionRepo) Revoke(ctx context.Context, plaintext string) error {
	hash := crypto.HashToken(plaintext)

	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query:     `UPDATE sessions SET revoked_at = ? WHERE session_hash = ? AND revoked_at IS NULL`,
			Arguments: []interface{}{formatTimestamp(time.Now()), hash},
		},
	})
	if err != nil {
		return fmt.Errorf("storage: revoke session: %w", err)
	}
	if results[0].Err != nil {
		return fmt.Errorf("storage: revoke session: %w", results[0].Err)
	}
	return nil
}

// RevokeAll ends every session of userID - used when the account is
// recovered, so anyone holding an old session is signed out.
func (r *SessionRepo) RevokeAll(ctx context.Context, userID int64) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{
		Query:     `UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		Arguments: []interface{}{nowTimestamp(), userID},
	}})
	return writeErr("revoke all sessions", results, err)
}
