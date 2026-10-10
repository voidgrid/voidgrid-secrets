package storage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func TestSecretLifecycle(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewSecretRepo(db, make([]byte, crypto.KeySize))

	s, err := repo.Create(ctx, "db-password", []byte("v1"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got, err := repo.Reveal(ctx, s.ID); err != nil || string(got) != "v1" {
		t.Fatalf("Reveal = %q, %v", got, err)
	}
	if _, err := repo.Create(ctx, "db-password", []byte("x")); !errors.Is(err, storage.ErrSecretNameTaken) {
		t.Fatalf("duplicate name: %v", err)
	}

	if _, err := repo.Update(ctx, s.ID, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.Reveal(ctx, s.ID); string(got) != "v2" {
		t.Fatalf("after update: %q", got)
	}

	other, err := repo.Create(ctx, "api-key", []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Rename(ctx, s.ID, "api-key"); !errors.Is(err, storage.ErrSecretNameTaken) {
		t.Fatalf("rename onto a taken name: %v", err)
	}
	renamed, err := repo.Rename(ctx, s.ID, "postgres-password")
	if err != nil || renamed.Name != "postgres-password" {
		t.Fatalf("Rename = %+v, %v", renamed, err)
	}
	// The encryption is bound to the id, not the name: still readable.
	if got, _ := repo.Reveal(ctx, s.ID); string(got) != "v2" {
		t.Fatalf("after rename: %q", got)
	}

	list, err := repo.List(ctx)
	if err != nil || len(list) != 2 || list[0].Name != "api-key" {
		t.Fatalf("List = %+v, %v", list, err)
	}

	if err := repo.Delete(ctx, other.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Reveal(ctx, other.ID); !errors.Is(err, storage.ErrSecretNotFound) {
		t.Fatalf("deleted secret: %v", err)
	}
	if err := repo.Delete(ctx, other.ID); !errors.Is(err, storage.ErrSecretNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestSecretRevealFailsWithWrongRootKey(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	key := make([]byte, crypto.KeySize)
	s, err := storage.NewSecretRepo(db, key).Create(ctx, "s", []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	other := make([]byte, crypto.KeySize)
	other[0] = 1
	if _, err := storage.NewSecretRepo(db, other).Reveal(ctx, s.ID); err == nil {
		t.Fatal("revealed with the wrong root key")
	}
}

// Someone with database write access (but not the root key) copies one
// secret's encrypted columns onto another: it must not decrypt there.
func TestSecretEncryptionIsBoundToItsRow(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewSecretRepo(db, make([]byte, crypto.KeySize))
	a, err := repo.Create(ctx, "a", []byte("value-a"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := repo.Create(ctx, "b", []byte("value-b"))
	if err != nil {
		t.Fatal(err)
	}
	rawExec(t, db, `UPDATE secrets SET
		wrapped_dek = (SELECT wrapped_dek FROM secrets WHERE id = ?),
		dek_nonce = (SELECT dek_nonce FROM secrets WHERE id = ?),
		ciphertext = (SELECT ciphertext FROM secrets WHERE id = ?),
		value_nonce = (SELECT value_nonce FROM secrets WHERE id = ?)
		WHERE id = ?`, b.ID, b.ID, b.ID, b.ID, a.ID)
	if got, err := repo.Reveal(ctx, a.ID); err == nil {
		t.Fatalf("swapped columns decrypted as %q", got)
	}
	if got, err := repo.Reveal(ctx, b.ID); err != nil || string(got) != "value-b" {
		t.Fatalf("Reveal(b) = %q, %v", got, err)
	}
}
