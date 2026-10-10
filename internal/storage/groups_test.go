package storage_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func TestGroupLifecycleAndNames(t *testing.T) {
	db, _ := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewGroupRepo(db)

	g, err := repo.Create(ctx, "  arr  ")
	if err != nil || g.Name != "arr" {
		t.Fatalf("Create = %+v, %v", g, err)
	}
	if _, err := repo.Create(ctx, "ARR"); !errors.Is(err, storage.ErrGroupNameTaken) {
		t.Fatalf("same name, different case: %v", err)
	}
	for _, bad := range []string{"", "   ", strings.Repeat("x", storage.MaxGroupNameLen+1), "a\nb"} {
		if _, err := repo.Create(ctx, bad); !errors.Is(err, storage.ErrInvalidGroupName) {
			t.Errorf("Create(%q) = %v, want ErrInvalidGroupName", bad, err)
		}
	}
	other, err := repo.Create(ctx, "media")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Rename(ctx, other.ID, "arr"); !errors.Is(err, storage.ErrGroupNameTaken) {
		t.Fatalf("rename onto a taken name: %v", err)
	}
	if err := repo.Rename(ctx, other.ID, "Media Stack"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if err := repo.Rename(ctx, 9999, "x"); !errors.Is(err, storage.ErrGroupNotFound) {
		t.Fatalf("rename unknown: %v", err)
	}
	list, err := repo.List(ctx)
	if err != nil || len(list) != 2 || list[0].Name != "arr" || list[1].Name != "Media Stack" {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if err := repo.Delete(ctx, g.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := repo.Delete(ctx, g.ID); !errors.Is(err, storage.ErrGroupNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if _, err := repo.Get(ctx, g.ID); !errors.Is(err, storage.ErrGroupNotFound) {
		t.Fatalf("Get deleted: %v", err)
	}
}

func TestGroupMembersAreSetAtomicallyAndFollowSecrets(t *testing.T) {
	db, _ := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewGroupRepo(db)
	secrets := storage.NewSecretRepo(db, make([]byte, crypto.KeySize))
	a, b, c := createTestSecret(t, db, "a"), createTestSecret(t, db, "b"), createTestSecret(t, db, "c")
	g, err := repo.Create(ctx, "arr")
	if err != nil {
		t.Fatal(err)
	}
	second, err := repo.Create(ctx, "other")
	if err != nil {
		t.Fatal(err)
	}

	if err := repo.SetMembers(ctx, g.ID, []int64{a.ID, b.ID, b.ID}); err != nil {
		t.Fatalf("SetMembers: %v", err)
	}
	if err := repo.SetMembers(ctx, second.ID, []int64{b.ID, c.ID}); err != nil {
		t.Fatalf("SetMembers (a secret in two groups): %v", err)
	}
	got, _ := repo.Get(ctx, g.ID)
	if !reflect.DeepEqual(got.SecretIDs, []int64{a.ID, b.ID}) {
		t.Fatalf("members = %v", got.SecretIDs)
	}

	// An unknown secret refuses the whole change.
	if err := repo.SetMembers(ctx, g.ID, []int64{c.ID, 9999}); !errors.Is(err, storage.ErrSecretNotFound) {
		t.Fatalf("unknown secret: %v", err)
	}
	if got, _ := repo.Get(ctx, g.ID); !reflect.DeepEqual(got.SecretIDs, []int64{a.ID, b.ID}) {
		t.Fatalf("failed change altered the group: %v", got.SecretIDs)
	}
	if err := repo.SetMembers(ctx, 9999, nil); !errors.Is(err, storage.ErrGroupNotFound) {
		t.Fatalf("unknown group: %v", err)
	}

	// Emptying a group works.
	if err := repo.SetMembers(ctx, g.ID, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.Get(ctx, g.ID); len(got.SecretIDs) != 0 {
		t.Fatalf("members after emptying = %v", got.SecretIDs)
	}

	// Deleting a secret drops it from its groups; deleting a group keeps the secrets.
	if err := secrets.Delete(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.Get(ctx, second.ID); !reflect.DeepEqual(got.SecretIDs, []int64{c.ID}) {
		t.Fatalf("members after deleting a secret = %v", got.SecretIDs)
	}
	if err := repo.Delete(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.Get(ctx, c.ID); err != nil {
		t.Fatalf("deleting a group removed a secret: %v", err)
	}
	all, err := repo.List(ctx)
	if err != nil || len(all) != 1 || len(all[0].SecretIDs) != 0 {
		t.Fatalf("List after deletes = %+v, %v", all, err)
	}
}
