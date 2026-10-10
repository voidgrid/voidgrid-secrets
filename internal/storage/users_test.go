package storage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func TestAccountDoesNotExistUntilSetup(t *testing.T) {
	db := newTestDB(t)
	repo := storage.NewUserRepo(db, make([]byte, crypto.KeySize))
	if _, err := repo.Get(context.Background()); !errors.Is(err, storage.ErrUserNotFound) {
		t.Fatalf("Get = %v, want ErrUserNotFound", err)
	}
}

func TestPasswordAccountRoundTrip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewUserRepo(db, make([]byte, crypto.KeySize))

	u, err := repo.SetupPassword(ctx, "owner", "hash-1")
	if err != nil || u.ID != storage.AccountID || u.AuthMethod != model.AuthPasswordTOTP {
		t.Fatalf("SetupPassword = %+v, %v", u, err)
	}
	rec, err := repo.GetAuthRecord(ctx, "owner")
	if err != nil || rec.PasswordHash != "hash-1" || rec.TOTPSecret != "" {
		t.Fatalf("before TOTP: %+v, %v", rec, err)
	}
	if err := repo.SetTOTPSecret(ctx, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetPassword(ctx, "hash-2"); err != nil {
		t.Fatal(err)
	}
	rec, err = repo.GetAuthRecord(ctx, "owner")
	if err != nil || rec.PasswordHash != "hash-2" || rec.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("after updates: %+v, %v", rec, err)
	}
	if _, err := repo.GetAuthRecord(ctx, "someone-else"); !errors.Is(err, storage.ErrUserNotFound) {
		t.Fatalf("wrong username: %v", err)
	}
}

// Setup can be restarted before it's confirmed; there is still only one
// account afterwards.
func TestSetupReplacesTheOneAccount(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewUserRepo(db, make([]byte, crypto.KeySize))

	if _, err := repo.SetupPassword(ctx, "first", "h"); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetTOTPSecret(ctx, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	u, err := repo.SetupOIDC(ctx, "second", "subject-2")
	if err != nil || u.ID != storage.AccountID || u.Username != "second" || u.AuthMethod != model.AuthOIDC {
		t.Fatalf("SetupOIDC = %+v, %v", u, err)
	}
	rec, err := repo.AuthRecord(ctx)
	if err != nil || rec.PasswordHash != "" || rec.TOTPSecret != "" || rec.OIDCSubject != "subject-2" {
		t.Fatalf("replaced account kept old credentials: %+v, %v", rec, err)
	}
}

func TestOIDCOwnerAcceptsOnlyTheAccountsIdentity(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewUserRepo(db, make([]byte, crypto.KeySize))

	if _, err := repo.OIDCOwner(ctx, "subject-1"); !errors.Is(err, storage.ErrUserNotFound) {
		t.Fatalf("no account yet: %v", err)
	}
	if _, err := repo.SetupOIDC(ctx, "", "subject-1"); err != nil {
		t.Fatal(err)
	}
	if u, err := repo.OIDCOwner(ctx, "subject-1"); err != nil || u.Username != "subject-1" {
		t.Fatalf("owner: %+v, %v", u, err)
	}
	if _, err := repo.OIDCOwner(ctx, "subject-2"); !errors.Is(err, storage.ErrNotOwner) {
		t.Fatalf("other identity: %v, want ErrNotOwner", err)
	}
}
