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

// ErrInvalidEnvName is returned by AddACL for an environment variable name
// that isn't uppercase letters, digits and underscores, or for an env name
// on a group grant (env names only apply to secret grants).
var ErrInvalidEnvName = errors.New("storage: invalid environment variable name")

// ErrEnvNameTaken is returned by AddACL when a secret grant's effective
// environment variable name is already used by another of the same
// token's secret grants - `voidgrid-secrets run` couldn't expose both.
var ErrEnvNameTaken = errors.New("storage: environment variable name already used by another grant on this token")

// ErrSecretNotFound is returned by AddACL when granting a secret that
// doesn't exist.
var ErrSecretNotFound = errors.New("storage: secret not found")

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

// AddACL grants token id permission on the given resource. For a secret
// grant, envName is the environment variable name `voidgrid-secrets run`
// exposes it under, or "" to derive one from the secret's name; the
// effective name must not collide with another of this token's secret
// grants. Group grants take no env name.
func (r *TokenRepo) AddACL(ctx context.Context, tokenID int64, resourceType string, resourceID int64, permission, envName string) error {
	var storedEnvName interface{}
	if resourceType == "secret" {
		effective, err := r.effectiveEnvName(ctx, resourceID, envName)
		if err != nil {
			return err
		}
		grants, err := r.EnvGrants(ctx, tokenID)
		if err != nil {
			return err
		}
		for _, g := range grants {
			if g.EnvName == effective {
				return fmt.Errorf("%w: %s", ErrEnvNameTaken, effective)
			}
		}
		if envName != "" {
			storedEnvName = envName
		}
	} else if envName != "" {
		return fmt.Errorf("%w: env names only apply to secret grants", ErrInvalidEnvName)
	}

	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query: `INSERT INTO machine_token_acls (token_id, resource_type, resource_id, permission, env_name)
				VALUES (?, ?, ?, ?, ?)`,
			Arguments: []interface{}{tokenID, resourceType, resourceID, permission, storedEnvName},
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

// ListACLs returns every grant on token id.
func (r *TokenRepo) ListACLs(ctx context.Context, tokenID int64) ([]model.TokenACL, error) {
	return r.listACLs(ctx, tokenID)
}

func (r *TokenRepo) listACLs(ctx context.Context, tokenID int64) ([]model.TokenACL, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query:     `SELECT token_id, resource_type, resource_id, permission, env_name FROM machine_token_acls WHERE token_id = ?`,
		Arguments: []interface{}{tokenID},
	})
	if err != nil {
		return nil, fmt.Errorf("storage: list ACLs for token %d: %w", tokenID, err)
	}

	var acls []model.TokenACL
	for qr.Next() {
		var (
			acl     model.TokenACL
			envName gorqlite.NullString
		)
		if err := qr.Scan(&acl.TokenID, &acl.ResourceType, &acl.ResourceID, &acl.Permission, &envName); err != nil {
			return nil, fmt.Errorf("storage: scan ACL for token %d: %w", tokenID, err)
		}
		acl.EnvName = envName.String
		acls = append(acls, acl)
	}
	return acls, nil
}

// EnvGrants returns every secret token id is granted (read or write),
// each with its effective environment variable name: the grant's explicit
// name, or one derived from the secret's name. Ordered by secret ID.
func (r *TokenRepo) EnvGrants(ctx context.Context, tokenID int64) ([]model.EnvGrant, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `SELECT s.id, s.name, a.env_name, a.permission
			FROM machine_token_acls a JOIN secrets s ON s.id = a.resource_id
			WHERE a.token_id = ? AND a.resource_type = 'secret'
			ORDER BY s.id`,
		Arguments: []interface{}{tokenID},
	})
	if err != nil {
		return nil, fmt.Errorf("storage: list env grants for token %d: %w", tokenID, err)
	}

	var grants []model.EnvGrant
	for qr.Next() {
		var (
			g       model.EnvGrant
			envName gorqlite.NullString
		)
		if err := qr.Scan(&g.SecretID, &g.SecretName, &envName, &g.Permission); err != nil {
			return nil, fmt.Errorf("storage: scan env grant for token %d: %w", tokenID, err)
		}
		g.EnvName = envName.String
		if g.EnvName == "" {
			g.EnvName = envname.Derive(g.SecretName)
		}
		grants = append(grants, g)
	}
	return grants, nil
}

// effectiveEnvName validates an explicit env name, or derives one from the
// secret's name when envName is empty.
func (r *TokenRepo) effectiveEnvName(ctx context.Context, secretID int64, envName string) (string, error) {
	if envName != "" {
		if !envname.Valid(envName) {
			return "", fmt.Errorf("%w: %q", ErrInvalidEnvName, envName)
		}
		if _, err := r.secretName(ctx, secretID); err != nil {
			return "", err
		}
		return envName, nil
	}
	name, err := r.secretName(ctx, secretID)
	if err != nil {
		return "", err
	}
	return envname.Derive(name), nil
}

func (r *TokenRepo) secretName(ctx context.Context, secretID int64) (string, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query:     `SELECT name FROM secrets WHERE id = ?`,
		Arguments: []interface{}{secretID},
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
