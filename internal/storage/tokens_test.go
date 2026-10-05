package storage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	authtoken "github.com/voidgrid/voidgrid-secrets/internal/auth/token"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func createTestSecret(t *testing.T, db *storage.DB, ownerID int64, name string) model.Secret {
	t.Helper()
	repo := storage.NewSecretRepo(db, make([]byte, crypto.KeySize))
	s, err := repo.Create(context.Background(), model.OwnerUser, ownerID, name, []byte("value-of-"+name), ownerID)
	if err != nil {
		t.Fatalf("create secret %q: %v", name, err)
	}
	return s
}

func TestTokenRepoCreateAndAuthenticate(t *testing.T) {
	db, baseURL := newTestDB(t)
	userID := insertTestUser(t, baseURL, "token-owner")
	repo := storage.NewTokenRepo(db)

	plaintext, mt, err := repo.Create(context.Background(), "ci runner", userID, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if mt.ID == 0 {
		t.Fatal("expected a non-zero token ID")
	}
	if mt.Description != "ci runner" {
		t.Fatalf("got description %q, want %q", mt.Description, "ci runner")
	}
	if mt.RevokedAt != nil || mt.ExpiresAt != nil {
		t.Fatalf("expected a fresh token to have no revoked/expires timestamps, got %+v", mt)
	}

	secret := createTestSecret(t, db, userID, "ci-secret")
	if err := repo.AddACL(context.Background(), mt.ID, "secret", secret.ID, "read", ""); err != nil {
		t.Fatalf("AddACL: %v", err)
	}

	gotMT, acls, err := repo.Authenticate(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if gotMT.ID != mt.ID {
		t.Fatalf("got token ID %d, want %d", gotMT.ID, mt.ID)
	}
	if len(acls) != 1 || !authtoken.CanAccess(acls, "secret", secret.ID, "read") {
		t.Fatalf("expected ACL granting read on secret %d, got %+v", secret.ID, acls)
	}
	if gotMT.LastUsedAt == nil {
		t.Fatal("expected LastUsedAt to be set after Authenticate")
	}
}

func TestTokenRepoAuthenticateRejectsWrongToken(t *testing.T) {
	db, baseURL := newTestDB(t)
	userID := insertTestUser(t, baseURL, "token-owner-2")
	repo := storage.NewTokenRepo(db)

	if _, _, err := repo.Create(context.Background(), "x", userID, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, _, err := repo.Authenticate(context.Background(), "vgs_this-token-does-not-exist")
	if !errors.Is(err, authtoken.ErrInvalidToken) {
		t.Fatalf("got err = %v, want ErrInvalidToken", err)
	}
}

func TestTokenRepoAuthenticateRejectsRevoked(t *testing.T) {
	db, baseURL := newTestDB(t)
	userID := insertTestUser(t, baseURL, "token-owner-3")
	repo := storage.NewTokenRepo(db)

	plaintext, mt, err := repo.Create(context.Background(), "x", userID, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := repo.Revoke(context.Background(), mt.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, _, err = repo.Authenticate(context.Background(), plaintext)
	if !errors.Is(err, authtoken.ErrInvalidToken) {
		t.Fatalf("got err = %v, want ErrInvalidToken", err)
	}
}

func TestTokenRepoAuthenticateRejectsExpired(t *testing.T) {
	db, baseURL := newTestDB(t)
	userID := insertTestUser(t, baseURL, "token-owner-4")
	repo := storage.NewTokenRepo(db)

	past := time.Now().Add(-time.Hour)
	plaintext, _, err := repo.Create(context.Background(), "x", userID, &past)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, _, err = repo.Authenticate(context.Background(), plaintext)
	if !errors.Is(err, authtoken.ErrInvalidToken) {
		t.Fatalf("got err = %v, want ErrInvalidToken", err)
	}
}

func TestTokenRepoEnvGrantsUseExplicitOrDerivedNames(t *testing.T) {
	db, baseURL := newTestDB(t)
	userID := insertTestUser(t, baseURL, "env-owner")
	repo := storage.NewTokenRepo(db)
	ctx := context.Background()

	_, mt, err := repo.Create(ctx, "svc", userID, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	dbPass := createTestSecret(t, db, userID, "db-password")
	apiKey := createTestSecret(t, db, userID, "api-key")

	if err := repo.AddACL(ctx, mt.ID, "secret", dbPass.ID, "read", "POSTGRES_PASSWORD"); err != nil {
		t.Fatalf("AddACL explicit: %v", err)
	}
	if err := repo.AddACL(ctx, mt.ID, "secret", apiKey.ID, "write", ""); err != nil {
		t.Fatalf("AddACL derived: %v", err)
	}

	grants, err := repo.EnvGrants(ctx, mt.ID)
	if err != nil {
		t.Fatalf("EnvGrants: %v", err)
	}
	got := map[int64]string{}
	for _, g := range grants {
		got[g.SecretID] = g.EnvName
	}
	if got[dbPass.ID] != "POSTGRES_PASSWORD" || got[apiKey.ID] != "API_KEY" || len(got) != 2 {
		t.Fatalf("got env names %v, want POSTGRES_PASSWORD and API_KEY", got)
	}
}

func TestTokenRepoAddACLRejectsEnvNameProblems(t *testing.T) {
	db, baseURL := newTestDB(t)
	userID := insertTestUser(t, baseURL, "env-owner-2")
	repo := storage.NewTokenRepo(db)
	ctx := context.Background()

	_, mt, err := repo.Create(ctx, "svc", userID, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	first := createTestSecret(t, db, userID, "db-password")
	second := createTestSecret(t, db, userID, "other")
	third := createTestSecret(t, db, userID, "third")

	if err := repo.AddACL(ctx, mt.ID, "secret", first.ID, "read", ""); err != nil {
		t.Fatalf("AddACL: %v", err)
	}

	if err := repo.AddACL(ctx, mt.ID, "secret", second.ID, "read", "DB_PASSWORD"); !errors.Is(err, storage.ErrEnvNameTaken) {
		t.Errorf("explicit name colliding with a derived one: got %v, want ErrEnvNameTaken", err)
	}
	if err := repo.AddACL(ctx, mt.ID, "secret", third.ID, "read", "lower-case"); !errors.Is(err, storage.ErrInvalidEnvName) {
		t.Errorf("invalid name: got %v, want ErrInvalidEnvName", err)
	}
	if err := repo.AddACL(ctx, mt.ID, "group", 1, "read", "SOME_NAME"); !errors.Is(err, storage.ErrInvalidEnvName) {
		t.Errorf("env name on a group grant: got %v, want ErrInvalidEnvName", err)
	}
	if err := repo.AddACL(ctx, mt.ID, "secret", 999999, "read", ""); !errors.Is(err, storage.ErrSecretNotFound) {
		t.Errorf("nonexistent secret: got %v, want ErrSecretNotFound", err)
	}

	grants, err := repo.EnvGrants(ctx, mt.ID)
	if err != nil {
		t.Fatalf("EnvGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("expected only the first grant to have been stored, got %+v", grants)
	}
}
