package storage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rqlite/gorqlite"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// Grants to ids that don't exist yet must be refused: otherwise whoever
// is given that id later inherits the grant.
func TestGrantsToMissingRecordsAreRefused(t *testing.T) {
	db, baseURL := newTestDB(t)
	ctx := context.Background()
	rootKey := make([]byte, crypto.KeySize)

	owner, err := storage.NewUserRepo(db, rootKey).CreateWithPassword(ctx, "ref-owner", "x")
	if err != nil {
		t.Fatal(err)
	}
	group, err := storage.NewGroupRepo(db).Create(ctx, "ref-group", "")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := storage.NewSecretRepo(db, rootKey).Create(ctx, model.OwnerUser, owner.ID, "ref-secret", []byte("v"), owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	tokens := storage.NewTokenRepo(db)
	_, mt, err := tokens.Create(ctx, "ref-token", owner.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	shares := storage.NewShareRepo(db)
	groups := storage.NewGroupRepo(db)
	const missing = 9999

	cases := []struct {
		name string
		err  error
	}{
		{"share with missing user", shares.Create(ctx, secret.ID, model.OwnerUser, missing, "read", owner.ID)},
		{"share with missing group", shares.Create(ctx, secret.ID, model.OwnerGroup, missing, "read", owner.ID)},
		{"share of missing secret", shares.Create(ctx, missing, model.OwnerUser, owner.ID, "read", owner.ID)},
		{"grant on missing token", tokens.AddACL(ctx, missing, "group", group.ID, "read", "")},
		{"grant of missing group", tokens.AddACL(ctx, mt.ID, "group", missing, "read", "")},
		{"member of missing group", groups.AddMember(ctx, missing, owner.ID, model.GroupRoleMember)},
		{"missing user into group", groups.AddMember(ctx, group.ID, missing, model.GroupRoleMember)},
	}
	for _, c := range cases {
		if !errors.Is(c.err, storage.ErrNotFound) {
			t.Errorf("%s: err = %v, want ErrNotFound", c.name, c.err)
		}
	}

	// The valid versions still work.
	if err := shares.Create(ctx, secret.ID, model.OwnerGroup, group.ID, "read", owner.ID); err != nil {
		t.Errorf("valid share: %v", err)
	}
	if err := tokens.AddACL(ctx, mt.ID, "group", group.ID, "read", ""); err != nil {
		t.Errorf("valid grant: %v", err)
	}
	if err := groups.AddMember(ctx, group.ID, owner.ID, model.GroupRoleMember); err != nil {
		t.Errorf("valid membership: %v", err)
	}

	// rqlited runs with -fk: a raw insert pointing at a missing user fails.
	conn, err := gorqlite.Open(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	res, err := conn.WriteParameterizedContext(ctx, []gorqlite.ParameterizedStatement{{
		Query:     `INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES (?, 'h', '2026-01-01T00:00:00.000Z')`,
		Arguments: []interface{}{missing},
	}})
	if err == nil && res[0].Err == nil {
		t.Fatal("foreign keys are not enforced")
	}

	violations, err := db.ForeignKeyViolations(ctx)
	if err != nil || len(violations) != 0 {
		t.Fatalf("ForeignKeyViolations = %v, %v; want none", violations, err)
	}
}
