package storage_test

import (
	"context"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func TestUserCanAccessOwnedSecret(t *testing.T) {
	db, baseURL := newTestDB(t)
	ctx := context.Background()
	rootKey := make([]byte, crypto.KeySize)
	secretRepo := storage.NewSecretRepo(db, rootKey)
	ownerID := insertTestUser(t, baseURL, "owner")

	s, err := secretRepo.Create(ctx, model.OwnerUser, ownerID, "s1", []byte("v"), ownerID)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	ok, err := secretRepo.UserCanAccess(ctx, ownerID, s.ID, "write")
	if err != nil {
		t.Fatalf("UserCanAccess: %v", err)
	}
	if !ok {
		t.Fatal("expected owner to have write access")
	}
}

func TestUserCanAccessDeniesUnrelatedUser(t *testing.T) {
	db, baseURL := newTestDB(t)
	ctx := context.Background()
	rootKey := make([]byte, crypto.KeySize)
	secretRepo := storage.NewSecretRepo(db, rootKey)
	ownerID := insertTestUser(t, baseURL, "owner2")
	otherID := insertTestUser(t, baseURL, "stranger")

	s, err := secretRepo.Create(ctx, model.OwnerUser, ownerID, "s1", []byte("v"), ownerID)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	ok, err := secretRepo.UserCanAccess(ctx, otherID, s.ID, "read")
	if err != nil {
		t.Fatalf("UserCanAccess: %v", err)
	}
	if ok {
		t.Fatal("expected an unrelated user to be denied access")
	}
}

func TestUserCanAccessViaDirectShare(t *testing.T) {
	db, baseURL := newTestDB(t)
	ctx := context.Background()
	rootKey := make([]byte, crypto.KeySize)
	secretRepo := storage.NewSecretRepo(db, rootKey)
	shareRepo := storage.NewShareRepo(db)
	ownerID := insertTestUser(t, baseURL, "owner3")
	granteeID := insertTestUser(t, baseURL, "grantee")

	s, err := secretRepo.Create(ctx, model.OwnerUser, ownerID, "s1", []byte("v"), ownerID)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if ok, _ := secretRepo.UserCanAccess(ctx, granteeID, s.ID, "read"); ok {
		t.Fatal("expected no access before sharing")
	}

	if err := shareRepo.Create(ctx, s.ID, model.OwnerUser, granteeID, "read", ownerID); err != nil {
		t.Fatalf("shareRepo.Create: %v", err)
	}

	ok, err := secretRepo.UserCanAccess(ctx, granteeID, s.ID, "read")
	if err != nil {
		t.Fatalf("UserCanAccess: %v", err)
	}
	if !ok {
		t.Fatal("expected grantee to have read access after sharing")
	}

	ok, err = secretRepo.UserCanAccess(ctx, granteeID, s.ID, "write")
	if err != nil {
		t.Fatalf("UserCanAccess: %v", err)
	}
	if ok {
		t.Fatal("expected a read-only share not to grant write access")
	}

	if err := shareRepo.Delete(ctx, s.ID, model.OwnerUser, granteeID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if ok, _ := secretRepo.UserCanAccess(ctx, granteeID, s.ID, "read"); ok {
		t.Fatal("expected access to be revoked after deleting the share")
	}
}

func TestUserCanAccessViaGroupOwnershipAndMembership(t *testing.T) {
	db, baseURL := newTestDB(t)
	ctx := context.Background()
	rootKey := make([]byte, crypto.KeySize)
	secretRepo := storage.NewSecretRepo(db, rootKey)
	groupRepo := storage.NewGroupRepo(db)
	ownerID := insertTestUser(t, baseURL, "group-owner")
	memberID := insertTestUser(t, baseURL, "plain-member")
	adminID := insertTestUser(t, baseURL, "group-admin-user")

	g, err := groupRepo.Create(ctx, "infra", "")
	if err != nil {
		t.Fatalf("groupRepo.Create: %v", err)
	}
	if err := groupRepo.AddMember(ctx, g.ID, memberID, model.GroupRoleMember); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if err := groupRepo.AddMember(ctx, g.ID, adminID, model.GroupRoleAdmin); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	s, err := secretRepo.Create(ctx, model.OwnerGroup, g.ID, "shared-secret", []byte("v"), ownerID)
	if err != nil {
		t.Fatalf("secretRepo.Create: %v", err)
	}

	if ok, err := secretRepo.UserCanAccess(ctx, memberID, s.ID, "read"); err != nil || !ok {
		t.Fatalf("expected plain member to have read access, ok=%v err=%v", ok, err)
	}
	if ok, err := secretRepo.UserCanAccess(ctx, memberID, s.ID, "write"); err != nil || ok {
		t.Fatalf("expected plain member NOT to have write access, ok=%v err=%v", ok, err)
	}
	if ok, err := secretRepo.UserCanAccess(ctx, adminID, s.ID, "write"); err != nil || !ok {
		t.Fatalf("expected group admin to have write access, ok=%v err=%v", ok, err)
	}
}
