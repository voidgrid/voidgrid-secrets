package storage_test

import (
	"context"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func TestAuthConfigRepoStartsIncomplete(t *testing.T) {
	db, _ := newTestDB(t)
	repo := storage.NewAuthConfigRepo(db, make([]byte, crypto.KeySize))

	complete, err := repo.IsComplete(context.Background())
	if err != nil {
		t.Fatalf("IsComplete: %v", err)
	}
	if complete {
		t.Fatal("expected a fresh DB to report setup incomplete")
	}
}

func TestAuthConfigRepoCompletePasswordTOTP(t *testing.T) {
	db, _ := newTestDB(t)
	repo := storage.NewAuthConfigRepo(db, make([]byte, crypto.KeySize))
	ctx := context.Background()

	if err := repo.CompletePasswordTOTP(ctx); err != nil {
		t.Fatalf("CompletePasswordTOTP: %v", err)
	}

	complete, err := repo.IsComplete(ctx)
	if err != nil {
		t.Fatalf("IsComplete: %v", err)
	}
	if !complete {
		t.Fatal("expected setup to be complete")
	}

	cfg, err := repo.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if cfg.AuthMethod != model.AuthPasswordTOTP {
		t.Fatalf("got auth method %q, want %q", cfg.AuthMethod, model.AuthPasswordTOTP)
	}
}

func TestAuthConfigRepoCompleteOIDCEncryptsClientSecret(t *testing.T) {
	db, _ := newTestDB(t)
	rootKey := make([]byte, crypto.KeySize)
	repo := storage.NewAuthConfigRepo(db, rootKey)
	ctx := context.Background()

	if err := repo.CompleteOIDC(ctx, "https://issuer.example", "client-id", "super-secret", "https://app.example/login/oidc/callback"); err != nil {
		t.Fatalf("CompleteOIDC: %v", err)
	}

	cfg, err := repo.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if cfg.AuthMethod != model.AuthOIDC {
		t.Fatalf("got auth method %q, want %q", cfg.AuthMethod, model.AuthOIDC)
	}
	if cfg.OIDCIssuer != "https://issuer.example" {
		t.Fatalf("got issuer %q, want %q", cfg.OIDCIssuer, "https://issuer.example")
	}
	if cfg.OIDCClientSecret != "super-secret" {
		t.Fatalf("got decrypted client secret %q, want %q", cfg.OIDCClientSecret, "super-secret")
	}
	if cfg.OIDCRedirectURI != "https://app.example/login/oidc/callback" {
		t.Fatalf("got redirect URI %q, want %q", cfg.OIDCRedirectURI, "https://app.example/login/oidc/callback")
	}
}
