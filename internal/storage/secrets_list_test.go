package storage_test

import (
	"context"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func TestSecretRepoListForUserIncludesOwnedGroupAndShared(t *testing.T) {
	db, baseURL := newTestDB(t)
	ctx := context.Background()
	rootKey := make([]byte, crypto.KeySize)
	secretRepo := storage.NewSecretRepo(db, rootKey)
	shareRepo := storage.NewShareRepo(db)
	groupRepo := storage.NewGroupRepo(db)

	owner := insertTestUser(t, baseURL, "list-owner")
	groupMember := insertTestUser(t, baseURL, "list-group-member")
	grantee := insertTestUser(t, baseURL, "list-grantee")
	unrelated := insertTestUser(t, baseURL, "list-unrelated")

	if _, err := secretRepo.Create(ctx, model.OwnerUser, owner, "owned", []byte("v"), owner); err != nil {
		t.Fatalf("Create owned: %v", err)
	}

	g, err := groupRepo.Create(ctx, "list-group", "")
	if err != nil {
		t.Fatalf("groupRepo.Create: %v", err)
	}
	if err := groupRepo.AddMember(ctx, g.ID, groupMember, model.GroupRoleMember); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	groupOwned, err := secretRepo.Create(ctx, model.OwnerGroup, g.ID, "group-owned", []byte("v"), owner)
	if err != nil {
		t.Fatalf("Create group-owned: %v", err)
	}

	sharedToGrantee, err := secretRepo.Create(ctx, model.OwnerUser, owner, "shared-with-grantee", []byte("v"), owner)
	if err != nil {
		t.Fatalf("Create shared: %v", err)
	}
	if err := shareRepo.Create(ctx, sharedToGrantee.ID, model.OwnerUser, grantee, "read", owner); err != nil {
		t.Fatalf("shareRepo.Create: %v", err)
	}

	// Owner sees the two secrets they directly own (the group-owned one
	// isn't theirs to see unless they're also a member of that group).
	ownerList, err := secretRepo.ListForUser(ctx, owner)
	if err != nil {
		t.Fatalf("ListForUser(owner): %v", err)
	}
	if len(ownerList) != 2 {
		t.Fatalf("owner: got %d secrets, want 2: %+v", len(ownerList), ownerList)
	}

	// Group member sees the group-owned secret only.
	memberList, err := secretRepo.ListForUser(ctx, groupMember)
	if err != nil {
		t.Fatalf("ListForUser(groupMember): %v", err)
	}
	if len(memberList) != 1 || memberList[0].ID != groupOwned.ID {
		t.Fatalf("groupMember: got %+v, want only %+v", memberList, groupOwned)
	}

	// Grantee sees the explicitly shared secret only.
	granteeList, err := secretRepo.ListForUser(ctx, grantee)
	if err != nil {
		t.Fatalf("ListForUser(grantee): %v", err)
	}
	if len(granteeList) != 1 || granteeList[0].ID != sharedToGrantee.ID {
		t.Fatalf("grantee: got %+v, want only %+v", granteeList, sharedToGrantee)
	}

	// Unrelated user sees nothing.
	unrelatedList, err := secretRepo.ListForUser(ctx, unrelated)
	if err != nil {
		t.Fatalf("ListForUser(unrelated): %v", err)
	}
	if len(unrelatedList) != 0 {
		t.Fatalf("unrelated: got %+v, want none", unrelatedList)
	}
}
