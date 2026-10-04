package storage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func TestUserRepoCreateWithPasswordAndGetAuthRecord(t *testing.T) {
	db, _ := newTestDB(t)
	rootKey := make([]byte, crypto.KeySize)
	repo := storage.NewUserRepo(db, rootKey)
	ctx := context.Background()

	user, err := repo.CreateWithPassword(ctx, "alice", "hashed-password")
	if err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}
	if user.AuthMethod != model.AuthPasswordTOTP {
		t.Fatalf("got auth method %q, want %q", user.AuthMethod, model.AuthPasswordTOTP)
	}

	if err := repo.SetTOTPSecret(ctx, user.ID, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("SetTOTPSecret: %v", err)
	}

	rec, err := repo.GetAuthRecord(ctx, "alice")
	if err != nil {
		t.Fatalf("GetAuthRecord: %v", err)
	}
	if rec.PasswordHash != "hashed-password" {
		t.Fatalf("got password hash %q, want %q", rec.PasswordHash, "hashed-password")
	}
	if rec.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("got TOTP secret %q, want %q", rec.TOTPSecret, "JBSWY3DPEHPK3PXP")
	}
}

func TestUserRepoGetAuthRecordBeforeTOTPEnrollmentHasEmptySecret(t *testing.T) {
	db, _ := newTestDB(t)
	rootKey := make([]byte, crypto.KeySize)
	repo := storage.NewUserRepo(db, rootKey)
	ctx := context.Background()

	if _, err := repo.CreateWithPassword(ctx, "bob", "hashed-password"); err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}

	rec, err := repo.GetAuthRecord(ctx, "bob")
	if err != nil {
		t.Fatalf("GetAuthRecord: %v", err)
	}
	if rec.TOTPSecret != "" {
		t.Fatalf("expected empty TOTP secret before enrollment, got %q", rec.TOTPSecret)
	}
}

func TestUserRepoCreateWithOIDCAndLookupBySubject(t *testing.T) {
	db, _ := newTestDB(t)
	rootKey := make([]byte, crypto.KeySize)
	repo := storage.NewUserRepo(db, rootKey)
	ctx := context.Background()

	created, err := repo.CreateWithOIDC(ctx, "carol", "oidc-subject-123")
	if err != nil {
		t.Fatalf("CreateWithOIDC: %v", err)
	}
	if created.AuthMethod != model.AuthOIDC {
		t.Fatalf("got auth method %q, want %q", created.AuthMethod, model.AuthOIDC)
	}

	found, err := repo.GetByOIDCSubject(ctx, "oidc-subject-123")
	if err != nil {
		t.Fatalf("GetByOIDCSubject: %v", err)
	}
	if found.ID != created.ID {
		t.Fatalf("got user ID %d, want %d", found.ID, created.ID)
	}
}

func TestUserRepoCountUsers(t *testing.T) {
	db, _ := newTestDB(t)
	rootKey := make([]byte, crypto.KeySize)
	repo := storage.NewUserRepo(db, rootKey)
	ctx := context.Background()

	n, err := repo.CountUsers(ctx)
	if err != nil {
		t.Fatalf("CountUsers: %v", err)
	}
	if n != 0 {
		t.Fatalf("got count %d, want 0 on a fresh DB", n)
	}

	if _, err := repo.CreateWithPassword(ctx, "dave", "x"); err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}

	n, err = repo.CountUsers(ctx)
	if err != nil {
		t.Fatalf("CountUsers: %v", err)
	}
	if n != 1 {
		t.Fatalf("got count %d, want 1", n)
	}
}

func TestGetOrCreateUserCreatesAndPromotesFirstUserToAdmin(t *testing.T) {
	db, _ := newTestDB(t)
	rootKey := make([]byte, crypto.KeySize)
	repo := storage.NewUserRepo(db, rootKey)
	ctx := context.Background()

	userID, created, err := repo.GetOrCreateUser(ctx, "subject-1", "alice")
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	if !created {
		t.Fatal("expected created=true for a new subject")
	}

	u, err := repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if u.AuthMethod != model.AuthOIDC {
		t.Fatalf("got auth method %q, want %q", u.AuthMethod, model.AuthOIDC)
	}
	if !u.IsAdmin {
		t.Fatal("expected the first user (regardless of auth method) to be promoted to admin")
	}
}

func TestGetOrCreateUserFindsExistingSubjectWithoutCreating(t *testing.T) {
	db, _ := newTestDB(t)
	rootKey := make([]byte, crypto.KeySize)
	repo := storage.NewUserRepo(db, rootKey)
	ctx := context.Background()

	firstID, _, err := repo.GetOrCreateUser(ctx, "subject-1", "alice")
	if err != nil {
		t.Fatalf("GetOrCreateUser (first call): %v", err)
	}

	secondID, created, err := repo.GetOrCreateUser(ctx, "subject-1", "alice")
	if err != nil {
		t.Fatalf("GetOrCreateUser (second call): %v", err)
	}
	if created {
		t.Fatal("expected created=false when the subject already has a user")
	}
	if secondID != firstID {
		t.Fatalf("got user ID %d, want %d (the existing user)", secondID, firstID)
	}
}

func TestGetOrCreateUserDoesNotPromoteSecondUser(t *testing.T) {
	db, _ := newTestDB(t)
	rootKey := make([]byte, crypto.KeySize)
	repo := storage.NewUserRepo(db, rootKey)
	ctx := context.Background()

	if _, _, err := repo.GetOrCreateUser(ctx, "subject-1", "alice"); err != nil {
		t.Fatalf("GetOrCreateUser (first): %v", err)
	}

	secondID, _, err := repo.GetOrCreateUser(ctx, "subject-2", "bob")
	if err != nil {
		t.Fatalf("GetOrCreateUser (second): %v", err)
	}

	u, err := repo.GetByID(ctx, secondID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if u.IsAdmin {
		t.Fatal("expected only the first user ever created to be promoted to admin")
	}
}

func TestGetOrCreateUserRejectsDisabledUser(t *testing.T) {
	db, _ := newTestDB(t)
	rootKey := make([]byte, crypto.KeySize)
	repo := storage.NewUserRepo(db, rootKey)
	ctx := context.Background()

	userID, _, err := repo.GetOrCreateUser(ctx, "subject-1", "alice")
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	if err := repo.SetDisabled(ctx, userID, true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}

	_, _, err = repo.GetOrCreateUser(ctx, "subject-1", "alice")
	if !errors.Is(err, model.ErrAccountDisabled) {
		t.Fatalf("got err = %v, want ErrAccountDisabled", err)
	}
}

func TestGetOrCreateUserFallsBackToSubjectOnUsernameCollision(t *testing.T) {
	db, _ := newTestDB(t)
	rootKey := make([]byte, crypto.KeySize)
	repo := storage.NewUserRepo(db, rootKey)
	ctx := context.Background()

	existing, err := repo.CreateWithPassword(ctx, "alice", "hashed-password")
	if err != nil {
		t.Fatalf("CreateWithPassword: %v", err)
	}

	userID, created, err := repo.GetOrCreateUser(ctx, "subject-1", "alice")
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	if !created || userID == existing.ID {
		t.Fatalf("got userID=%d created=%v, want a new user distinct from %d", userID, created, existing.ID)
	}

	u, err := repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if u.Username != "subject-1" {
		t.Fatalf("got username %q, want fallback to subject %q", u.Username, "subject-1")
	}
	if u.IsAdmin {
		t.Fatal("expected a non-first user not to be promoted to admin")
	}
}
