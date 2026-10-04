package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/rqlite/gorqlite"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/token"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// TokenRepo provides access to machine tokens and their resource ACLs.
// It implements token.Authenticator.
type TokenRepo struct {
	db *DB
}

// NewTokenRepo returns a TokenRepo backed by db.
func NewTokenRepo(db *DB) *TokenRepo {
	return &TokenRepo{db: db}
}

// Create generates a new machine token, stores only its hash, and returns
// the plaintext token (shown to the caller exactly once) along with its
// stored metadata.
func (r *TokenRepo) Create(ctx context.Context, description string, createdBy int64, expiresAt *time.Time) (plaintext string, mt model.MachineToken, err error) {
	plaintext, err = token.Generate()
	if err != nil {
		return "", model.MachineToken{}, err
	}
	hash := crypto.HashToken(plaintext)

	var expiresArg interface{}
	if expiresAt != nil {
		expiresArg = formatTimestamp(*expiresAt)
	}

	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query:     `INSERT INTO machine_tokens (token_hash, description, created_by, expires_at) VALUES (?, ?, ?, ?)`,
			Arguments: []interface{}{hash, description, createdBy, expiresArg},
		},
	})
	if err != nil {
		return "", model.MachineToken{}, fmt.Errorf("storage: insert machine token: %w", err)
	}
	if results[0].Err != nil {
		return "", model.MachineToken{}, fmt.Errorf("storage: insert machine token: %w", results[0].Err)
	}

	mt, err = r.getByID(ctx, results[0].LastInsertID)
	if err != nil {
		return "", model.MachineToken{}, err
	}
	return plaintext, mt, nil
}

// Authenticate implements token.Authenticator: it hashes plaintext, looks
// up the matching token, rejects it if revoked or expired, records
// last_used_at, and returns the token's metadata and ACLs.
func (r *TokenRepo) Authenticate(ctx context.Context, plaintext string) (model.MachineToken, []model.TokenACL, error) {
	hash := crypto.HashToken(plaintext)

	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `SELECT id, description, created_by, created_at, expires_at, revoked_at, last_used_at
			FROM machine_tokens WHERE token_hash = ?`,
		Arguments: []interface{}{hash},
	})
	if err != nil {
		return model.MachineToken{}, nil, fmt.Errorf("storage: authenticate token: %w", err)
	}
	if !qr.Next() {
		return model.MachineToken{}, nil, token.ErrInvalidToken
	}

	mt, err := scanMachineToken(qr)
	if err != nil {
		return model.MachineToken{}, nil, fmt.Errorf("storage: scan machine token: %w", err)
	}

	if mt.RevokedAt != nil {
		return model.MachineToken{}, nil, token.ErrInvalidToken
	}
	if mt.ExpiresAt != nil && mt.ExpiresAt.Before(time.Now()) {
		return model.MachineToken{}, nil, token.ErrInvalidToken
	}

	acls, err := r.listACLs(ctx, mt.ID)
	if err != nil {
		return model.MachineToken{}, nil, err
	}

	now := time.Now()
	if _, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query:     `UPDATE machine_tokens SET last_used_at = ? WHERE id = ?`,
			Arguments: []interface{}{formatTimestamp(now), mt.ID},
		},
	}); err != nil {
		return model.MachineToken{}, nil, fmt.Errorf("storage: record token use: %w", err)
	}
	mt.LastUsedAt = &now

	return mt, acls, nil
}

// Revoke marks a machine token as revoked immediately.
func (r *TokenRepo) Revoke(ctx context.Context, id int64) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query:     `UPDATE machine_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
			Arguments: []interface{}{formatTimestamp(time.Now()), id},
		},
	})
	if err != nil {
		return fmt.Errorf("storage: revoke token %d: %w", id, err)
	}
	if results[0].Err != nil {
		return fmt.Errorf("storage: revoke token %d: %w", id, results[0].Err)
	}
	return nil
}

// AddACL grants token id permission on the given resource.
func (r *TokenRepo) AddACL(ctx context.Context, tokenID int64, resourceType string, resourceID int64, permission string) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query: `INSERT INTO machine_token_acls (token_id, resource_type, resource_id, permission)
				VALUES (?, ?, ?, ?)`,
			Arguments: []interface{}{tokenID, resourceType, resourceID, permission},
		},
	})
	if err != nil {
		return fmt.Errorf("storage: add ACL for token %d: %w", tokenID, err)
	}
	if results[0].Err != nil {
		return fmt.Errorf("storage: add ACL for token %d: %w", tokenID, results[0].Err)
	}
	return nil
}

// List returns every machine token (for the admin token-management
// screen), newest first.
func (r *TokenRepo) List(ctx context.Context) ([]model.MachineToken, error) {
	qr, err := r.db.conn.QueryContext(ctx, []string{
		`SELECT id, description, created_by, created_at, expires_at, revoked_at, last_used_at
			FROM machine_tokens ORDER BY id DESC`,
	})
	if err != nil {
		return nil, fmt.Errorf("storage: list tokens: %w", err)
	}
	if len(qr) == 0 {
		return nil, fmt.Errorf("storage: list tokens: no result")
	}

	var tokens []model.MachineToken
	for qr[0].Next() {
		mt, err := scanMachineToken(qr[0])
		if err != nil {
			return nil, fmt.Errorf("storage: scan token: %w", err)
		}
		tokens = append(tokens, mt)
	}
	return tokens, nil
}

func (r *TokenRepo) listACLs(ctx context.Context, tokenID int64) ([]model.TokenACL, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query:     `SELECT token_id, resource_type, resource_id, permission FROM machine_token_acls WHERE token_id = ?`,
		Arguments: []interface{}{tokenID},
	})
	if err != nil {
		return nil, fmt.Errorf("storage: list ACLs for token %d: %w", tokenID, err)
	}

	var acls []model.TokenACL
	for qr.Next() {
		var acl model.TokenACL
		if err := qr.Scan(&acl.TokenID, &acl.ResourceType, &acl.ResourceID, &acl.Permission); err != nil {
			return nil, fmt.Errorf("storage: scan ACL for token %d: %w", tokenID, err)
		}
		acls = append(acls, acl)
	}
	return acls, nil
}

func (r *TokenRepo) getByID(ctx context.Context, id int64) (model.MachineToken, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `SELECT id, description, created_by, created_at, expires_at, revoked_at, last_used_at
			FROM machine_tokens WHERE id = ?`,
		Arguments: []interface{}{id},
	})
	if err != nil {
		return model.MachineToken{}, fmt.Errorf("storage: get token %d: %w", id, err)
	}
	if !qr.Next() {
		return model.MachineToken{}, fmt.Errorf("storage: token %d not found", id)
	}
	return scanMachineToken(qr)
}

func scanMachineToken(qr gorqlite.QueryResult) (model.MachineToken, error) {
	var (
		mt           model.MachineToken
		createdAtRaw string
		expiresAt    gorqlite.NullString
		revokedAt    gorqlite.NullString
		lastUsedAt   gorqlite.NullString
	)
	if err := qr.Scan(&mt.ID, &mt.Description, &mt.CreatedBy, &createdAtRaw, &expiresAt, &revokedAt, &lastUsedAt); err != nil {
		return model.MachineToken{}, err
	}

	var err error
	mt.CreatedAt, err = parseTimestamp(createdAtRaw)
	if err != nil {
		return model.MachineToken{}, fmt.Errorf("parse created_at: %w", err)
	}
	mt.ExpiresAt, err = parseNullableTimestamp(expiresAt.String, expiresAt.Valid)
	if err != nil {
		return model.MachineToken{}, fmt.Errorf("parse expires_at: %w", err)
	}
	mt.RevokedAt, err = parseNullableTimestamp(revokedAt.String, revokedAt.Valid)
	if err != nil {
		return model.MachineToken{}, fmt.Errorf("parse revoked_at: %w", err)
	}
	mt.LastUsedAt, err = parseNullableTimestamp(lastUsedAt.String, lastUsedAt.Valid)
	if err != nil {
		return model.MachineToken{}, fmt.Errorf("parse last_used_at: %w", err)
	}

	return mt, nil
}
