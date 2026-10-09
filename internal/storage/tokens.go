package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rqlite/gorqlite"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/token"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/envname"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// ErrInvalidEnvName is returned by AddGrant for an environment variable
// name that isn't uppercase letters, digits and underscores.
var ErrInvalidEnvName = errors.New("storage: invalid environment variable name")

// ErrEnvNameTaken is returned by AddGrant when the grant's effective
// environment variable name is already used by another of the same
// token's grants - `voidgrid-secrets run` couldn't expose both.
var ErrEnvNameTaken = errors.New("storage: environment variable name already used by another grant on this token")

// TokenRepo provides access to machine tokens and their per-secret grants.
// It implements token.Authenticator.
type TokenRepo struct {
	db *DB
}

// NewTokenRepo returns a TokenRepo backed by db.
func NewTokenRepo(db *DB) *TokenRepo {
	return &TokenRepo{db: db}
}

const tokenColumns = `id, description, created_at, expires_at, revoked_at, last_used_at`

// Create generates a new machine token, stores only its hash, and returns
// the plaintext token (shown to the caller exactly once) with its stored
// metadata.
func (r *TokenRepo) Create(ctx context.Context, description string, expiresAt *time.Time) (plaintext string, mt model.MachineToken, err error) {
	plaintext, err = token.Generate()
	if err != nil {
		return "", model.MachineToken{}, err
	}
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{
		Query:     `INSERT INTO machine_tokens (token_hash, description, expires_at, created_at) VALUES (?, ?, ?, ?)`,
		Arguments: []interface{}{crypto.HashToken(plaintext), description, timeOrNil(expiresAt), nowTimestamp()},
	}})
	if err := writeErr("create machine token", results, err); err != nil {
		return "", model.MachineToken{}, err
	}
	mt, err = r.Get(ctx, results[0].LastInsertID)
	if err != nil {
		return "", model.MachineToken{}, err
	}
	return plaintext, mt, nil
}

// Authenticate implements token.Authenticator: it hashes plaintext, looks
// up the matching token, rejects it if revoked or expired, records
// last_used_at, and returns the token's metadata and grants.
func (r *TokenRepo) Authenticate(ctx context.Context, plaintext string) (model.MachineToken, []model.TokenGrant, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query:     `SELECT ` + tokenColumns + ` FROM machine_tokens WHERE token_hash = ?`,
		Arguments: []interface{}{crypto.HashToken(plaintext)},
	})
	if err != nil {
		return model.MachineToken{}, nil, fmt.Errorf("storage: authenticate token: %w", err)
	}
	if !qr.Next() {
		return model.MachineToken{}, nil, token.ErrInvalidToken
	}
	mt, err := scanMachineToken(qr)
	if err != nil {
		return model.MachineToken{}, nil, err
	}
	if mt.RevokedAt != nil || (mt.ExpiresAt != nil && mt.ExpiresAt.Before(time.Now())) {
		return model.MachineToken{}, nil, token.ErrInvalidToken
	}

	grants, err := r.ListGrants(ctx, mt.ID)
	if err != nil {
		return model.MachineToken{}, nil, err
	}

	now := time.Now()
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{
		Query: `UPDATE machine_tokens SET last_used_at = ? WHERE id = ?`, Arguments: []interface{}{formatTimestamp(now), mt.ID},
	}})
	if err := writeErr("record token use", results, err); err != nil {
		return model.MachineToken{}, nil, err
	}
	mt.LastUsedAt = &now
	return mt, grants, nil
}

// Revoke marks a token revoked; it can never authenticate again.
func (r *TokenRepo) Revoke(ctx context.Context, id int64) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{
		Query:     `UPDATE machine_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		Arguments: []interface{}{nowTimestamp(), id},
	}})
	return writeErr("revoke token", results, err)
}

// AddGrant gives token tokenID permission ("read" or "write") on a secret,
// exposed to `run` and the agent under envName - or, if envName is empty,
// a name derived from the secret's name. Grants whose effective names
// collide on one token are refused. Both the token and the secret must
// exist.
func (r *TokenRepo) AddGrant(ctx context.Context, tokenID, secretID int64, permission, envName string) error {
	if envName != "" && !envname.Valid(envName) {
		return fmt.Errorf("%w: %q", ErrInvalidEnvName, envName)
	}
	effective := envName
	if effective == "" {
		name, err := r.secretName(ctx, secretID)
		if err != nil {
			return err
		}
		effective = envname.Derive(name)
	}
	existing, err := r.EnvGrants(ctx, tokenID)
	if err != nil {
		return err
	}
	for _, g := range existing {
		if g.EnvName == effective && g.SecretID != secretID {
			return fmt.Errorf("%w: %s", ErrEnvNameTaken, effective)
		}
	}

	var stored interface{}
	if envName != "" {
		stored = envName
	}
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{
		Query: `INSERT INTO machine_token_grants (token_id, secret_id, permission, env_name)
			SELECT ?, ?, ?, ?
			WHERE EXISTS (SELECT 1 FROM machine_tokens WHERE id = ?) AND EXISTS (SELECT 1 FROM secrets WHERE id = ?)
			ON CONFLICT (token_id, secret_id) DO UPDATE SET permission = excluded.permission, env_name = excluded.env_name`,
		Arguments: []interface{}{tokenID, secretID, permission, stored, tokenID, secretID},
	}})
	if err := writeErr("add grant", results, err); err != nil {
		return err
	}
	if results[0].RowsAffected == 0 {
		return fmt.Errorf("%w: token %d or secret %d", ErrNotFound, tokenID, secretID)
	}
	return nil
}

// RemoveGrant takes away a token's grant on one secret. It returns
// ErrNotFound if the token has no such grant.
func (r *TokenRepo) RemoveGrant(ctx context.Context, tokenID, secretID int64) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{
		Query:     `DELETE FROM machine_token_grants WHERE token_id = ? AND secret_id = ?`,
		Arguments: []interface{}{tokenID, secretID},
	}})
	if err := writeErr("remove grant", results, err); err != nil {
		return err
	}
	if results[0].RowsAffected == 0 {
		return fmt.Errorf("%w: token %d has no grant on secret %d", ErrNotFound, tokenID, secretID)
	}
	return nil
}

// List returns every machine token, newest first.
func (r *TokenRepo) List(ctx context.Context) ([]model.MachineToken, error) {
	qr, err := r.db.conn.QueryOneContext(ctx, `SELECT `+tokenColumns+` FROM machine_tokens ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("storage: list tokens: %w", err)
	}
	tokens := []model.MachineToken{}
	for qr.Next() {
		mt, err := scanMachineToken(qr)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, mt)
	}
	return tokens, nil
}

// Get returns one token's metadata.
func (r *TokenRepo) Get(ctx context.Context, id int64) (model.MachineToken, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `SELECT ` + tokenColumns + ` FROM machine_tokens WHERE id = ?`, Arguments: []interface{}{id},
	})
	if err != nil {
		return model.MachineToken{}, fmt.Errorf("storage: get token %d: %w", id, err)
	}
	if !qr.Next() {
		return model.MachineToken{}, fmt.Errorf("%w: token %d", ErrNotFound, id)
	}
	return scanMachineToken(qr)
}

// ListGrants returns every grant on a token, with the secret's name.
func (r *TokenRepo) ListGrants(ctx context.Context, tokenID int64) ([]model.TokenGrant, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `SELECT g.token_id, g.secret_id, s.name, g.permission, g.env_name
			FROM machine_token_grants g JOIN secrets s ON s.id = g.secret_id
			WHERE g.token_id = ? ORDER BY s.name`,
		Arguments: []interface{}{tokenID},
	})
	if err != nil {
		return nil, fmt.Errorf("storage: list grants for token %d: %w", tokenID, err)
	}
	grants := []model.TokenGrant{}
	for qr.Next() {
		var (
			g       model.TokenGrant
			envName gorqlite.NullString
		)
		if err := qr.Scan(&g.TokenID, &g.SecretID, &g.SecretName, &g.Permission, &envName); err != nil {
			return nil, fmt.Errorf("storage: scan grant: %w", err)
		}
		g.EnvName = envName.String
		grants = append(grants, g)
	}
	return grants, nil
}

// EnvGrants returns a token's grants with each one's effective environment
// variable name (explicit, or derived from the secret's current name) and
// when the secret's value last changed.
func (r *TokenRepo) EnvGrants(ctx context.Context, tokenID int64) ([]model.EnvGrant, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `SELECT s.id, s.name, g.env_name, g.permission, s.updated_at
			FROM machine_token_grants g JOIN secrets s ON s.id = g.secret_id
			WHERE g.token_id = ? ORDER BY s.id`,
		Arguments: []interface{}{tokenID},
	})
	if err != nil {
		return nil, fmt.Errorf("storage: list env grants for token %d: %w", tokenID, err)
	}
	var grants []model.EnvGrant
	for qr.Next() {
		var (
			g          model.EnvGrant
			envName    gorqlite.NullString
			updatedRaw string
		)
		if err := qr.Scan(&g.SecretID, &g.SecretName, &envName, &g.Permission, &updatedRaw); err != nil {
			return nil, fmt.Errorf("storage: scan env grant: %w", err)
		}
		if g.SecretUpdatedAt, err = parseTimestamp(updatedRaw); err != nil {
			return nil, fmt.Errorf("storage: parse updated_at of secret %d: %w", g.SecretID, err)
		}
		g.EnvName = envName.String
		if g.EnvName == "" {
			g.EnvName = envname.Derive(g.SecretName)
		}
		grants = append(grants, g)
	}
	return grants, nil
}

func (r *TokenRepo) secretName(ctx context.Context, secretID int64) (string, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `SELECT name FROM secrets WHERE id = ?`, Arguments: []interface{}{secretID},
	})
	if err != nil {
		return "", fmt.Errorf("storage: look up secret %d: %w", secretID, err)
	}
	if !qr.Next() {
		return "", fmt.Errorf("%w: %d", ErrSecretNotFound, secretID)
	}
	var name string
	if err := qr.Scan(&name); err != nil {
		return "", fmt.Errorf("storage: scan secret %d name: %w", secretID, err)
	}
	return name, nil
}

func scanMachineToken(qr gorqlite.QueryResult) (model.MachineToken, error) {
	var (
		mt                               model.MachineToken
		createdAtRaw                     string
		expiresAt, revokedAt, lastUsedAt gorqlite.NullString
	)
	if err := qr.Scan(&mt.ID, &mt.Description, &createdAtRaw, &expiresAt, &revokedAt, &lastUsedAt); err != nil {
		return model.MachineToken{}, fmt.Errorf("storage: scan token: %w", err)
	}
	var err error
	if mt.CreatedAt, err = parseTimestamp(createdAtRaw); err != nil {
		return model.MachineToken{}, fmt.Errorf("storage: parse token created_at: %w", err)
	}
	if mt.ExpiresAt, err = parseNullableTimestamp(expiresAt.String, expiresAt.Valid); err != nil {
		return model.MachineToken{}, fmt.Errorf("storage: parse token expires_at: %w", err)
	}
	if mt.RevokedAt, err = parseNullableTimestamp(revokedAt.String, revokedAt.Valid); err != nil {
		return model.MachineToken{}, fmt.Errorf("storage: parse token revoked_at: %w", err)
	}
	if mt.LastUsedAt, err = parseNullableTimestamp(lastUsedAt.String, lastUsedAt.Valid); err != nil {
		return model.MachineToken{}, fmt.Errorf("storage: parse token last_used_at: %w", err)
	}
	return mt, nil
}
