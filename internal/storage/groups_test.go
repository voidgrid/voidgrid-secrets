package storage_test

import (
	"context"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func TestGroupRepoCreateAndListMembers(t *testing.T) {
	db, baseURL := newTestDB(t)
	ctx := context.Background()
	groupRepo := storage.NewGroupRepo(db)
	userID := insertTestUser(t, baseURL, "group-member")

	g, err := groupRepo.Create(ctx, "infra", "infrastructure team")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if g.Name != "infra" {
		t.Fatalf("got name %q, want %q", g.Name, "infra")
	}

	if err := groupRepo.AddMember(ctx, g.ID, userID, model.GroupRoleAdmin); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	members, err := groupRepo.ListMembers(ctx, g.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 1 || members[0].UserID != userID || members[0].Role != model.GroupRoleAdmin {
		t.Fatalf("got members %+v, want one admin member with ID %d", members, userID)
	}

	if err := groupRepo.RemoveMember(ctx, g.ID, userID); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	members, err = groupRepo.ListMembers(ctx, g.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 0 {
		t.Fatalf("expected no members after removal, got %+v", members)
	}
}

func TestGroupRepoAddMemberUpsertsRole(t *testing.T) {
	db, baseURL := newTestDB(t)
	ctx := context.Background()
	groupRepo := storage.NewGroupRepo(db)
	userID := insertTestUser(t, baseURL, "role-change-user")

	g, err := groupRepo.Create(ctx, "team", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := groupRepo.AddMember(ctx, g.ID, userID, model.GroupRoleMember); err != nil {
		t.Fatalf("AddMember (member): %v", err)
	}
	if err := groupRepo.AddMember(ctx, g.ID, userID, model.GroupRoleAdmin); err != nil {
		t.Fatalf("AddMember (admin): %v", err)
	}

	members, err := groupRepo.ListMembers(ctx, g.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 1 || members[0].Role != model.GroupRoleAdmin {
		t.Fatalf("expected role to be upgraded to admin, got %+v", members)
	}
}

func TestGroupRepoList(t *testing.T) {
	db, _ := newTestDB(t)
	ctx := context.Background()
	groupRepo := storage.NewGroupRepo(db)

	if _, err := groupRepo.Create(ctx, "a", ""); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := groupRepo.Create(ctx, "b", ""); err != nil {
		t.Fatalf("Create: %v", err)
	}

	groups, err := groupRepo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(groups))
	}
}
