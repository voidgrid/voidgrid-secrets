package storage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	authtoken "github.com/voidgrid/voidgrid-secrets/internal/auth/token"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

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

	if err := repo.AddACL(context.Background(), mt.ID, "secret", 7, "read"); err != nil {
		t.Fatalf("AddACL: %v", err)
	}

	gotMT, acls, err := repo.Authenticate(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if gotMT.ID != mt.ID {
		t.Fatalf("got token ID %d, want %d", gotMT.ID, mt.ID)
	}
	if len(acls) != 1 || !authtoken.CanAccess(acls, "secret", 7, "read") {
		t.Fatalf("expected ACL granting read on secret 7, got %+v", acls)
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
