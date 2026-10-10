package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rqlite/gorqlite"

	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

// ErrGroupNotFound is returned when no group has the given id.
var ErrGroupNotFound = errors.New("storage: group not found")

// ErrGroupNameTaken is returned when another group already has the name
// (compared case-insensitively).
var ErrGroupNameTaken = errors.New("storage: group name already taken")

// ErrInvalidGroupName is returned for an empty, over-long or control-
// character group name.
var ErrInvalidGroupName = errors.New("storage: invalid group name")

// MaxGroupNameLen is the longest group name, in characters.
const MaxGroupNameLen = 64

// GroupRepo manages secret groups: a UI-only convenience for ticking
// several secrets together. Nothing about grants refers to them.
type GroupRepo struct {
	db *DB
}

// NewGroupRepo returns a GroupRepo backed by db.
func NewGroupRepo(db *DB) *GroupRepo {
	return &GroupRepo{db: db}
}

func cleanGroupName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > MaxGroupNameLen {
		return "", fmt.Errorf("%w: use 1-%d characters", ErrInvalidGroupName, MaxGroupNameLen)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("%w: no control characters", ErrInvalidGroupName)
		}
	}
	return name, nil
}

func isGroupNameViolation(err error) bool {
	return strings.Contains(err.Error(), "UNIQUE constraint failed: secret_groups.name")
}

// Create adds an empty group.
func (r *GroupRepo) Create(ctx context.Context, name string) (model.SecretGroup, error) {
	name, err := cleanGroupName(name)
	if err != nil {
		return model.SecretGroup{}, err
	}
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{
		Query:     `INSERT INTO secret_groups (name, created_at) VALUES (?, ?)`,
		Arguments: []interface{}{name, nowTimestamp()},
	}})
	if err := writeErr("create group", results, err); err != nil {
		if isGroupNameViolation(err) {
			return model.SecretGroup{}, ErrGroupNameTaken
		}
		return model.SecretGroup{}, err
	}
	return r.Get(ctx, results[0].LastInsertID)
}

// List returns every group with its members, ordered by name.
func (r *GroupRepo) List(ctx context.Context) ([]model.SecretGroup, error) {
	qr, err := r.db.conn.QueryOneContext(ctx, `SELECT id, name, created_at FROM secret_groups ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("storage: list groups: %w", err)
	}
	groups := []model.SecretGroup{}
	index := map[int64]int{}
	for qr.Next() {
		g, err := scanGroup(qr)
		if err != nil {
			return nil, err
		}
		index[g.ID] = len(groups)
		groups = append(groups, g)
	}

	mr, err := r.db.conn.QueryOneContext(ctx, `SELECT group_id, secret_id FROM secret_group_members ORDER BY group_id, secret_id`)
	if err != nil {
		return nil, fmt.Errorf("storage: list group members: %w", err)
	}
	for mr.Next() {
		var gid, sid int64
		if err := mr.Scan(&gid, &sid); err != nil {
			return nil, fmt.Errorf("storage: scan group member: %w", err)
		}
		if i, ok := index[gid]; ok {
			groups[i].SecretIDs = append(groups[i].SecretIDs, sid)
		}
	}
	return groups, nil
}

// Get returns one group with its members.
func (r *GroupRepo) Get(ctx context.Context, id int64) (model.SecretGroup, error) {
	qr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `SELECT id, name, created_at FROM secret_groups WHERE id = ?`, Arguments: []interface{}{id},
	})
	if err != nil {
		return model.SecretGroup{}, fmt.Errorf("storage: get group %d: %w", id, err)
	}
	if !qr.Next() {
		return model.SecretGroup{}, fmt.Errorf("%w: %d", ErrGroupNotFound, id)
	}
	g, err := scanGroup(qr)
	if err != nil {
		return model.SecretGroup{}, err
	}
	mr, err := r.db.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `SELECT secret_id FROM secret_group_members WHERE group_id = ? ORDER BY secret_id`, Arguments: []interface{}{id},
	})
	if err != nil {
		return model.SecretGroup{}, fmt.Errorf("storage: list members of group %d: %w", id, err)
	}
	for mr.Next() {
		var sid int64
		if err := mr.Scan(&sid); err != nil {
			return model.SecretGroup{}, fmt.Errorf("storage: scan group member: %w", err)
		}
		g.SecretIDs = append(g.SecretIDs, sid)
	}
	return g, nil
}

func scanGroup(qr gorqlite.QueryResult) (model.SecretGroup, error) {
	var (
		g   model.SecretGroup
		raw string
	)
	if err := qr.Scan(&g.ID, &g.Name, &raw); err != nil {
		return model.SecretGroup{}, fmt.Errorf("storage: scan group: %w", err)
	}
	var err error
	if g.CreatedAt, err = parseTimestamp(raw); err != nil {
		return model.SecretGroup{}, fmt.Errorf("storage: parse group created_at: %w", err)
	}
	return g, nil
}

// Rename changes a group's name.
func (r *GroupRepo) Rename(ctx context.Context, id int64, name string) error {
	name, err := cleanGroupName(name)
	if err != nil {
		return err
	}
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{
		Query: `UPDATE secret_groups SET name = ? WHERE id = ?`, Arguments: []interface{}{name, id},
	}})
	if err := writeErr("rename group", results, err); err != nil {
		if isGroupNameViolation(err) {
			return ErrGroupNameTaken
		}
		return err
	}
	if results[0].RowsAffected == 0 {
		return fmt.Errorf("%w: %d", ErrGroupNotFound, id)
	}
	return nil
}

// Delete removes a group and its memberships. The secrets and every grant
// are untouched.
func (r *GroupRepo) Delete(ctx context.Context, id int64) error {
	results, err := r.db.conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{
		Query: `DELETE FROM secret_groups WHERE id = ?`, Arguments: []interface{}{id},
	}})
	if err := writeErr("delete group", results, err); err != nil {
		return err
	}
	if results[0].RowsAffected == 0 {
		return fmt.Errorf("%w: %d", ErrGroupNotFound, id)
	}
	return nil
}

// SetMembers makes secretIDs exactly the group's members, in one
// transaction. Unknown secrets are refused (ErrSecretNotFound) and leave
// the group unchanged.
func (r *GroupRepo) SetMembers(ctx context.Context, id int64, secretIDs []int64) error {
	if _, err := r.Get(ctx, id); err != nil {
		return err
	}
	stmts := []gorqlite.ParameterizedStatement{{
		Query: `DELETE FROM secret_group_members WHERE group_id = ?`, Arguments: []interface{}{id},
	}}
	seen := map[int64]bool{}
	for _, sid := range secretIDs {
		if seen[sid] {
			continue
		}
		seen[sid] = true
		stmts = append(stmts, gorqlite.ParameterizedStatement{
			Query: `INSERT INTO secret_group_members (group_id, secret_id) VALUES (?, ?)`, Arguments: []interface{}{id, sid},
		})
	}
	results, err := r.db.conn.WriteParameterizedContext(ctx, stmts)
	if err := writeErrAll("set group members", results, err); err != nil {
		if strings.Contains(err.Error(), "FOREIGN KEY") {
			return ErrSecretNotFound
		}
		return err
	}
	return nil
}

// writeErrAll is writeErr for multi-statement writes: it reports the first
// failing statement.
func writeErrAll(what string, results []gorqlite.WriteResult, err error) error {
	if err != nil {
		return fmt.Errorf("storage: %s: %w", what, err)
	}
	for _, res := range results {
		if res.Err != nil {
			return fmt.Errorf("storage: %s: %w", what, res.Err)
		}
	}
	return nil
}
