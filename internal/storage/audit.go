package storage

import (
	"context"
	"fmt"

	"github.com/rqlite/gorqlite"
)

// AuditRepo appends to the audit_log table. There is no viewer UI for it
// yet (listed as optional/low-priority in the project's design notes); the
// goal right now is just to ensure sensitive actions (reveal, in
// particular) leave a record even before one is built.
type AuditRepo struct {
	db *DB
}

// NewAuditRepo returns an AuditRepo backed by db.
func NewAuditRepo(db *DB) *AuditRepo {
	return &AuditRepo{db: db}
}

// Log records that actorType/actorID performed action on
// resourceType/resourceID.
func (r *AuditRepo) Log(ctx context.Context, actorType string, actorID int64, action, resourceType string, resourceID int64) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query: `INSERT INTO audit_log (actor_type, actor_id, action, resource_type, resource_id)
				VALUES (?, ?, ?, ?, ?)`,
			Arguments: []interface{}{actorType, actorID, action, resourceType, resourceID},
		},
	})
	if err != nil {
		return fmt.Errorf("storage: write audit log entry: %w", err)
	}
	if results[0].Err != nil {
		return fmt.Errorf("storage: write audit log entry: %w", results[0].Err)
	}
	return nil
}
