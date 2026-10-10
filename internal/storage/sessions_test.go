package storage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func TestSessionRepoCreateAndAuthenticate(t *testing.T) {
	db := newTestDB(t)
	userRepo := storage.NewUserRepo(db, make([]byte, crypto.KeySize))
	sessionRepo := storage.NewSessionRepo(db)
	ctx := context.Background()

	user, err := userRepo.SetupPassword(ctx, "alice", "x")
	if err != nil {
		t.Fatalf("SetupPassword: %v", err)
	}

	plaintext, expiresAt, err := sessionRepo.Create(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if expiresAt.Before(time.Now()) {
		t.Fatal("expected expiresAt to be in the future")
	}

	got, err := sessionRepo.Authenticate(ctx, plaintext)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.ID != user.ID {
		t.Fatalf("got user ID %d, want %d", got.ID, user.ID)
	}
}

func TestSessionRepoAuthenticateRejectsUnknownToken(t *testing.T) {
	db := newTestDB(t)
	sessionRepo := storage.NewSessionRepo(db)

	_, err := sessionRepo.Authenticate(context.Background(), "vgs_sess_does-not-exist")
	if !errors.Is(err, session.ErrInvalidSession) {
		t.Fatalf("got err = %v, want ErrInvalidSession", err)
	}
}

func TestSessionRepoAuthenticateRejectsExpired(t *testing.T) {
	db := newTestDB(t)
	userRepo := storage.NewUserRepo(db, make([]byte, crypto.KeySize))
	sessionRepo := storage.NewSessionRepo(db)
	ctx := context.Background()

	user, err := userRepo.SetupPassword(ctx, "bob", "x")
	if err != nil {
		t.Fatalf("SetupPassword: %v", err)
	}

	plaintext, _, err := sessionRepo.Create(ctx, user.ID, -time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err = sessionRepo.Authenticate(ctx, plaintext)
	if !errors.Is(err, session.ErrInvalidSession) {
		t.Fatalf("got err = %v, want ErrInvalidSession", err)
	}
}

func TestSessionRepoAuthenticateRejectsRevoked(t *testing.T) {
	db := newTestDB(t)
	userRepo := storage.NewUserRepo(db, make([]byte, crypto.KeySize))
	sessionRepo := storage.NewSessionRepo(db)
	ctx := context.Background()

	user, err := userRepo.SetupPassword(ctx, "carol", "x")
	if err != nil {
		t.Fatalf("SetupPassword: %v", err)
	}

	plaintext, _, err := sessionRepo.Create(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := sessionRepo.Revoke(ctx, plaintext); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, err = sessionRepo.Authenticate(ctx, plaintext)
	if !errors.Is(err, session.ErrInvalidSession) {
		t.Fatalf("got err = %v, want ErrInvalidSession", err)
	}
}
