package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
)

// AuditRepo appends to and reads the audit_log table.
type AuditRepo struct {
	db *DB
}

// NewAuditRepo returns an AuditRepo backed by db.
func NewAuditRepo(db *DB) *AuditRepo {
	return &AuditRepo{db: db}
}

// Log records e. Its details, plus where the request came from (see
// audit.Middleware), are stored as JSON in the metadata column.
func (r *AuditRepo) Log(ctx context.Context, e audit.Event) error {
	meta := map[string]string{}
	for k, v := range e.Details {
		meta[k] = v
	}
	if info, ok := audit.RequestFrom(ctx); ok {
		meta["ip"] = info.IP
		if info.ForwardedFor != "" {
			meta["forwarded_for"] = info.ForwardedFor
		}
		if info.UserAgent != "" {
			meta["user_agent"] = info.UserAgent
		}
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("storage: encode audit metadata: %w", err)
	}

	var resourceID interface{}
	if e.ResourceID != 0 {
		resourceID = e.ResourceID
	}
	results, err := r.db.write(ctx, []Statement{
		{
			Query: `INSERT INTO audit_log (actor_type, actor_id, action, resource_type, resource_id, metadata, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
			Arguments: []interface{}{e.Actor.Type, e.Actor.ID, e.Action, e.ResourceType, resourceID, string(metaJSON), nowTimestamp()},
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

// AuditEntry is one audit log row, with the name of a token or secret it
// refers to looked up (empty if it no longer exists or doesn't apply).
type AuditEntry struct {
	ID           int64             `json:"id"`
	At           time.Time         `json:"at"`
	ActorType    string            `json:"actor_type"`
	ActorID      int64             `json:"actor_id"`
	ActorName    string            `json:"actor_name"`
	Action       string            `json:"action"`
	ResourceType string            `json:"resource_type"`
	ResourceID   int64             `json:"resource_id"`
	ResourceName string            `json:"resource_name"`
	Details      map[string]string `json:"details"`
}

// AuditFilter narrows List. Zero values match everything.
type AuditFilter struct {
	Action string
	// TokenID matches entries where that token acted or was acted on.
	TokenID int64
	// BeforeID returns only entries older than this id (for paging).
	BeforeID int64
	// Limit defaults to 100 and is capped at 500.
	Limit int
}

// List returns entries matching f, newest first.
func (r *AuditRepo) List(ctx context.Context, f AuditFilter) ([]AuditEntry, error) {
	var (
		where []string
		args  []interface{}
	)
	if f.Action != "" {
		where = append(where, "a.action = ?")
		args = append(args, f.Action)
	}
	if f.TokenID != 0 {
		where = append(where, "((a.actor_type = 'token' AND a.actor_id = ?) OR (a.resource_type = 'token' AND a.resource_id = ?))")
		args = append(args, f.TokenID, f.TokenID)
	}
	if f.BeforeID != 0 {
		where = append(where, "a.id < ?")
		args = append(args, f.BeforeID)
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	query := `SELECT a.id, a.created_at, a.actor_type, a.actor_id, a.action, a.resource_type, COALESCE(a.resource_id, 0), a.metadata,
			CASE a.actor_type
				WHEN 'user' THEN (SELECT username FROM users WHERE id = a.actor_id)
				WHEN 'token' THEN (SELECT description FROM machine_tokens WHERE id = a.actor_id)
			END,
			CASE a.resource_type
				WHEN 'secret' THEN (SELECT name FROM secrets WHERE id = a.resource_id)
				WHEN 'token' THEN (SELECT description FROM machine_tokens WHERE id = a.resource_id)
				WHEN 'group' THEN (SELECT name FROM secret_groups WHERE id = a.resource_id)
			END
		FROM audit_log a`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY a.id DESC LIMIT ?"
	args = append(args, limit)

	qr, err := r.db.queryOne(ctx, Statement{Query: query, Arguments: args})
	if err != nil {
		return nil, fmt.Errorf("storage: list audit log: %w", err)
	}
	entries := []AuditEntry{}
	for qr.Next() {
		var (
			e                       AuditEntry
			atRaw, meta             string
			actorName, resourceName sql.NullString
		)
		if err := qr.Scan(&e.ID, &atRaw, &e.ActorType, &e.ActorID, &e.Action, &e.ResourceType, &e.ResourceID, &meta, &actorName, &resourceName); err != nil {
			return nil, fmt.Errorf("storage: scan audit entry: %w", err)
		}
		if e.At, err = parseTimestamp(atRaw); err != nil {
			return nil, fmt.Errorf("storage: parse audit timestamp: %w", err)
		}
		e.ActorName, e.ResourceName = actorName.String, resourceName.String
		e.Details = map[string]string{}
		_ = json.Unmarshal([]byte(meta), &e.Details)
		entries = append(entries, e)
	}
	return entries, nil
}

// Prune deletes entries recorded before cutoff and returns how many.
func (r *AuditRepo) Prune(ctx context.Context, cutoff time.Time) (int64, error) {
	results, err := r.db.write(ctx, []Statement{{
		Query: `DELETE FROM audit_log WHERE created_at < ?`, Arguments: []interface{}{formatTimestamp(cutoff)},
	}})
	if err := writeErr("prune audit log", results, err); err != nil {
		return 0, err
	}
	return results[0].RowsAffected, nil
}
