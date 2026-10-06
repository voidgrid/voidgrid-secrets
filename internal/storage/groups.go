package storage

import (
	"context"
	"fmt"

	"github.com/rqlite/gorqlite"

	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// GroupRepo provides access to the groups and user_groups tables.
type GroupRepo struct {
	db *DB
}

// NewGroupRepo returns a GroupRepo backed by db.
func NewGroupRepo(db *DB) *GroupRepo {
	return &GroupRepo{db: db}
}

// Create inserts a new group.
func (r *GroupRepo) Create(ctx context.Context, name, description string) (model.Group, error) {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query:     `INSERT INTO groups (name, description, created_at) VALUES (?, ?, ?)`,
			Arguments: []interface{}{name, description, nowTimestamp()},
		},
	})
	if err != nil {
		return model.Group{}, fmt.Errorf("storage: create group %q: %w", name, err)
	}
	if results[0].Err != nil {
		return model.Group{}, fmt.Errorf("storage: create group %q: %w", name, results[0].Err)
	}
	return r.GetByID(ctx, results[0].LastInsertID)
}

// GetByID returns a group by ID.
func (r *GroupRepo) GetByID(ctx context.Context, id int64) (model.Group, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query:     `SELECT id, name, description, created_at FROM groups WHERE id = ?`,
		Arguments: []interface{}{id},
	})
	if err != nil {
		return model.Group{}, fmt.Errorf("storage: get group %d: %w", id, err)
	}
	if !qr.Next() {
		return model.Group{}, fmt.Errorf("storage: group %d not found", id)
	}
	return scanGroup(qr)
}

// List returns every group.
func (r *GroupRepo) List(ctx context.Context) ([]model.Group, error) {
	qr, err := r.db.conn.QueryContext(ctx, []string{`SELECT id, name, description, created_at FROM groups ORDER BY id`})
	if err != nil {
		return nil, fmt.Errorf("storage: list groups: %w", err)
	}
	if len(qr) == 0 {
		return nil, fmt.Errorf("storage: list groups: no result")
	}

	var groups []model.Group
	for qr[0].Next() {
		g, err := scanGroup(qr[0])
		if err != nil {
			return nil, fmt.Errorf("storage: scan group: %w", err)
		}
		groups = append(groups, g)
	}
	return groups, nil
}

// AddMember adds userID to groupID with the given role, replacing any
// existing membership role for that pair.
func (r *GroupRepo) AddMember(ctx context.Context, groupID, userID int64, role model.GroupRole) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query: `INSERT INTO user_groups (user_id, group_id, role)
				SELECT ?, ?, ?
				WHERE EXISTS (SELECT 1 FROM users WHERE id = ?) AND EXISTS (SELECT 1 FROM groups WHERE id = ?)
				ON CONFLICT (user_id, group_id) DO UPDATE SET role = excluded.role`,
			Arguments: []interface{}{userID, groupID, string(role), userID, groupID},
		},
	})
	if err != nil {
		return fmt.Errorf("storage: add member %d to group %d: %w", userID, groupID, err)
	}
	if results[0].Err != nil {
		return fmt.Errorf("storage: add member %d to group %d: %w", userID, groupID, results[0].Err)
	}
	if results[0].RowsAffected == 0 {
		return fmt.Errorf("%w: user %d or group %d", ErrNotFound, userID, groupID)
	}
	return nil
}

// RemoveMember removes userID's membership in groupID.
func (r *GroupRepo) RemoveMember(ctx context.Context, groupID, userID int64) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{
		{
			Query:     `DELETE FROM user_groups WHERE group_id = ? AND user_id = ?`,
			Arguments: []interface{}{groupID, userID},
		},
	})
	if err != nil {
		return fmt.Errorf("storage: remove member %d from group %d: %w", userID, groupID, err)
	}
	if results[0].Err != nil {
		return fmt.Errorf("storage: remove member %d from group %d: %w", userID, groupID, results[0].Err)
	}
	return nil
}

// ListMembers returns every member of groupID.
func (r *GroupRepo) ListMembers(ctx context.Context, groupID int64) ([]model.GroupMember, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `SELECT ug.user_id, ug.group_id, u.username, ug.role
			FROM user_groups ug JOIN users u ON u.id = ug.user_id
			WHERE ug.group_id = ? ORDER BY u.username`,
		Arguments: []interface{}{groupID},
	})
	if err != nil {
		return nil, fmt.Errorf("storage: list members of group %d: %w", groupID, err)
	}

	var members []model.GroupMember
	for qr.Next() {
		var m model.GroupMember
		var role string
		if err := qr.Scan(&m.UserID, &m.GroupID, &m.Username, &role); err != nil {
			return nil, fmt.Errorf("storage: scan group member: %w", err)
		}
		m.Role = model.GroupRole(role)
		members = append(members, m)
	}
	return members, nil
}

func scanGroup(qr gorqlite.QueryResult) (model.Group, error) {
	var (
		g            model.Group
		createdAtRaw string
	)
	if err := qr.Scan(&g.ID, &g.Name, &g.Description, &createdAtRaw); err != nil {
		return model.Group{}, err
	}

	var err error
	g.CreatedAt, err = parseTimestamp(createdAtRaw)
	if err != nil {
		return model.Group{}, fmt.Errorf("parse created_at: %w", err)
	}
	return g, nil
}
