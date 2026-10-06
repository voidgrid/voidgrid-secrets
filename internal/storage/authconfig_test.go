package storage_test

import (
	"context"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func TestPasswordSetupCompletes(t *testing.T) {
	db, _ := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewAuthConfigRepo(db, make([]byte, crypto.KeySize))

	if done, err := repo.IsComplete(ctx); err != nil || done {
		t.Fatalf("fresh: complete = %v, %v", done, err)
	}
	if err := repo.CompletePasswordTOTP(ctx); err != nil {
		t.Fatal(err)
	}
	cfg, err := repo.Get(ctx)
	if err != nil || cfg.AuthMethod != model.AuthPasswordTOTP || cfg.CompletedAt == nil {
		t.Fatalf("Get = %+v, %v", cfg, err)
	}
}

// OIDC setup is pending until the operator signs in; the client secret is
// stored encrypted and read back intact.
func TestOIDCSetupIsPendingUntilCompleted(t *testing.T) {
	db, _ := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewAuthConfigRepo(db, make([]byte, crypto.KeySize))

	if err := repo.SaveOIDC(ctx, "https://issuer.example", "client-id", "s3cret", "https://app.example/cb"); err != nil {
		t.Fatal(err)
	}
	if done, _ := repo.IsComplete(ctx); done {
		t.Fatal("complete before the operator signed in")
	}
	cfg, err := repo.Get(ctx)
	if err != nil || cfg.OIDCClientSecret != "s3cret" || cfg.OIDCRedirectURI != "https://app.example/cb" || cfg.CompletedAt != nil {
		t.Fatalf("pending config = %+v, %v", cfg, err)
	}
	if err := repo.CompleteOIDC(ctx); err != nil {
		t.Fatal(err)
	}
	if done, _ := repo.IsComplete(ctx); !done {
		t.Fatal("not complete after CompleteOIDC")
	}
	if err := repo.CompleteOIDC(ctx); err == nil {
		t.Fatal("completed twice")
	}
}
