package storage_test

import (
	"context"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func TestRecoveryCodeRepoConsumeIsSingleUse(t *testing.T) {
	db, _ := newTestDB(t)
	rootKey := make([]byte, crypto.KeySize)
	users := storage.NewUserRepo(db, rootKey)
	codes := storage.NewRecoveryCodeRepo(db)
	ctx := context.Background()

	user, err := users.SetupPassword(ctx, "alice", "hashed-password")
	if err != nil {
		t.Fatalf("SetupPassword: %v", err)
	}

	hash := crypto.HashToken("ABCDE-FGHIJ-KLMNO")
	if err := codes.ReplaceForUser(ctx, user.ID, []string{hash}); err != nil {
		t.Fatalf("ReplaceForUser: %v", err)
	}

	ok, err := codes.Consume(ctx, user.ID, hash)
	if err != nil {
		t.Fatalf("Consume (first use): %v", err)
	}
	if !ok {
		t.Fatal("expected the first use of a valid code to succeed")
	}

	ok, err = codes.Consume(ctx, user.ID, hash)
	if err != nil {
		t.Fatalf("Consume (second use): %v", err)
	}
	if ok {
		t.Fatal("expected a second use of the same code to fail (single-use)")
	}
}

func TestRecoveryCodeRepoReplaceForUserInvalidatesOldCodes(t *testing.T) {
	db, _ := newTestDB(t)
	rootKey := make([]byte, crypto.KeySize)
	users := storage.NewUserRepo(db, rootKey)
	codes := storage.NewRecoveryCodeRepo(db)
	ctx := context.Background()

	user, err := users.SetupPassword(ctx, "alice", "hashed-password")
	if err != nil {
		t.Fatalf("SetupPassword: %v", err)
	}

	oldHash := crypto.HashToken("old-code")
	if err := codes.ReplaceForUser(ctx, user.ID, []string{oldHash}); err != nil {
		t.Fatalf("ReplaceForUser (first batch): %v", err)
	}

	newHash := crypto.HashToken("new-code")
	if err := codes.ReplaceForUser(ctx, user.ID, []string{newHash}); err != nil {
		t.Fatalf("ReplaceForUser (second batch): %v", err)
	}

	if ok, err := codes.Consume(ctx, user.ID, oldHash); err != nil || ok {
		t.Fatalf("got ok=%v err=%v, want the old code to no longer work after regenerating", ok, err)
	}
	if ok, err := codes.Consume(ctx, user.ID, newHash); err != nil || !ok {
		t.Fatalf("got ok=%v err=%v, want the new code to work", ok, err)
	}
}

func TestRecoveryCodeRepoConsumeRejectsUnknownCode(t *testing.T) {
	db, _ := newTestDB(t)
	rootKey := make([]byte, crypto.KeySize)
	users := storage.NewUserRepo(db, rootKey)
	codes := storage.NewRecoveryCodeRepo(db)
	ctx := context.Background()

	user, err := users.SetupPassword(ctx, "alice", "hashed-password")
	if err != nil {
		t.Fatalf("SetupPassword: %v", err)
	}

	ok, err := codes.Consume(ctx, user.ID, crypto.HashToken("never-issued"))
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if ok {
		t.Fatal("expected consuming a never-issued code to fail")
	}
}
