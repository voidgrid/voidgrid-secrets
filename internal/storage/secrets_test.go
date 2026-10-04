package storage_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// TestSecretRoundTrip is the Phase 2 walking skeleton: it proves
// create secret -> encrypted row in rqlite -> read back -> decrypt works
// end-to-end against a real rqlite instance before anything else (auth,
// API, UI) is built on top of this layer.
func TestSecretRoundTrip(t *testing.T) {
	db, baseURL := newTestDB(t)
	userID := insertTestUser(t, baseURL, "walking-skeleton")

	rootKey := make([]byte, crypto.KeySize)
	for i := range rootKey {
		rootKey[i] = byte(i)
	}
	repo := storage.NewSecretRepo(db, rootKey)

	plaintext := []byte("sk-super-secret-api-key")
	created, err := repo.Create(context.Background(), model.OwnerUser, userID, "my-api-key", plaintext, userID)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == 0 {
		t.Fatal("expected a non-zero secret ID")
	}
	if created.Name != "my-api-key" {
		t.Fatalf("got name %q, want %q", created.Name, "my-api-key")
	}
	if created.OwnerType != model.OwnerUser || created.OwnerID != userID {
		t.Fatalf("got owner (%s, %d), want (%s, %d)", created.OwnerType, created.OwnerID, model.OwnerUser, userID)
	}
	if created.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be populated")
	}

	fetched, err := repo.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if fetched != created {
		t.Fatalf("Get returned %+v, want %+v", fetched, created)
	}

	revealed, err := repo.Reveal(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	if !bytes.Equal(revealed, plaintext) {
		t.Fatalf("revealed %q, want %q", revealed, plaintext)
	}
}

// TestSecretRevealFailsWithWrongRootKey proves that a secret encrypted
// under one root key cannot be decrypted by a repository configured with a
// different root key, i.e. the root key genuinely gates access.
func TestSecretRevealFailsWithWrongRootKey(t *testing.T) {
	db, baseURL := newTestDB(t)
	userID := insertTestUser(t, baseURL, "wrong-key-user")

	rootKey := make([]byte, crypto.KeySize)
	repo := storage.NewSecretRepo(db, rootKey)

	created, err := repo.Create(context.Background(), model.OwnerUser, userID, "secret", []byte("value"), userID)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	wrongKey := make([]byte, crypto.KeySize)
	for i := range wrongKey {
		wrongKey[i] = 0xFF
	}
	otherRepo := storage.NewSecretRepo(db, wrongKey)

	if _, err := otherRepo.Reveal(context.Background(), created.ID); err == nil {
		t.Fatal("expected Reveal with the wrong root key to fail, got nil error")
	}
}
