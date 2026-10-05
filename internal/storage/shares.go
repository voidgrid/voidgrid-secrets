package storage

import (
	"context"
	"fmt"

	"github.com/rqlite/gorqlite"

	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// ShareRepo provides access to the secret_shares table: explicit grants of
// access to a secret beyond what its ownership already implies.
type ShareRepo struct {
	db *DB
}

// NewShareRepo returns a ShareRepo backed by db.
func NewShareRepo(db *DB) *ShareRepo {
	return &ShareRepo{db: db}
}

// Create grants granteeType/granteeID permission on secretID.
func (r *ShareRepo) Create(ctx context.Context, secretID int64, granteeType model.OwnerType, granteeID int64, permission string, grantedBy int64) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query: `INSERT INTO secret_shares (secret_id, grantee_type, grantee_id, permission, granted_by, granted_at)
				VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT (secret_id, grantee_type, grantee_id) DO UPDATE SET permission = excluded.permission`,
			Arguments: []interface{}{secretID, string(granteeType), granteeID, permission, grantedBy, nowTimestamp()},
		},
	})
	if err != nil {
		return fmt.Errorf("storage: share secret %d: %w", secretID, err)
	}
	if results[0].Err != nil {
		return fmt.Errorf("storage: share secret %d: %w", secretID, results[0].Err)
	}
	return nil
}

// Delete revokes a share.
func (r *ShareRepo) Delete(ctx context.Context, secretID int64, granteeType model.OwnerType, granteeID int64) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query:     `DELETE FROM secret_shares WHERE secret_id = ? AND grantee_type = ? AND grantee_id = ?`,
			Arguments: []interface{}{secretID, string(granteeType), granteeID},
		},
	})
	if err != nil {
		return fmt.Errorf("storage: delete share on secret %d: %w", secretID, err)
	}
	if results[0].Err != nil {
		return fmt.Errorf("storage: delete share on secret %d: %w", secretID, results[0].Err)
	}
	return nil
}

// List returns every share on a secret.
func (r *ShareRepo) List(ctx context.Context, secretID int64) ([]model.SecretShare, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `SELECT secret_id, grantee_type, grantee_id, permission, granted_by, granted_at
			FROM secret_shares WHERE secret_id = ? ORDER BY granted_at`,
		Arguments: []interface{}{secretID},
	})
	if err != nil {
		return nil, fmt.Errorf("storage: list shares on secret %d: %w", secretID, err)
	}

	var shares []model.SecretShare
	for qr.Next() {
		var (
			s            model.SecretShare
			granteeType  string
			grantedAtRaw string
		)
		if err := qr.Scan(&s.SecretID, &granteeType, &s.GranteeID, &s.Permission, &s.GrantedBy, &grantedAtRaw); err != nil {
			return nil, fmt.Errorf("storage: scan share on secret %d: %w", secretID, err)
		}
		s.GranteeType = model.OwnerType(granteeType)
		s.GrantedAt, err = parseTimestamp(grantedAtRaw)
		if err != nil {
			return nil, fmt.Errorf("storage: parse granted_at on secret %d: %w", secretID, err)
		}
		shares = append(shares, s)
	}
	return shares, nil
}
