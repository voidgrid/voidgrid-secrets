package storage_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/rqlite/gorqlite"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func rawExec(t *testing.T, baseURL, query string, args ...interface{}) {
	t.Helper()
	conn, err := gorqlite.Open(baseURL)
	if err != nil {
		t.Fatalf("open raw connection: %v", err)
	}
	defer conn.Close()
	res, err := conn.WriteParameterizedContext(context.Background(), []gorqlite.ParameterizedStatement{{Query: query, Arguments: args}})
	if err != nil || res[0].Err != nil {
		t.Fatalf("exec %q: %v %v", query, err, res[0].Err)
	}
}

func TestSecretEncryptionIsBoundToItsRow(t *testing.T) {
	db, baseURL := newTestDB(t)
	ctx := context.Background()
	rootKey := make([]byte, crypto.KeySize)
	users := storage.NewUserRepo(db, rootKey)
	secrets := storage.NewSecretRepo(db, rootKey)

	owner, err := users.CreateWithPassword(ctx, "aad-owner", "x")
	if err != nil {
		t.Fatal(err)
	}
	a, err := secrets.Create(ctx, model.OwnerUser, owner.ID, "a", []byte("value-a"), owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := secrets.Create(ctx, model.OwnerUser, owner.ID, "b", []byte("value-b"), owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := secrets.Reveal(ctx, a.ID); err != nil || string(got) != "value-a" {
		t.Fatalf("Reveal(a) = %q, %v", got, err)
	}

	// Someone with database write access copies b's encrypted columns
	// onto a. It must not decrypt as a.
	rawExec(t, baseURL, `UPDATE secrets SET
		wrapped_dek = (SELECT wrapped_dek FROM secrets WHERE id = ?),
		dek_nonce = (SELECT dek_nonce FROM secrets WHERE id = ?),
		ciphertext = (SELECT ciphertext FROM secrets WHERE id = ?),
		value_nonce = (SELECT value_nonce FROM secrets WHERE id = ?)
		WHERE id = ?`, b.ID, b.ID, b.ID, b.ID, a.ID)
	if got, err := secrets.Reveal(ctx, a.ID); err == nil {
		t.Fatalf("Reveal(a) after swap returned %q, want an error", got)
	}
	if got, err := secrets.Reveal(ctx, b.ID); err != nil || string(got) != "value-b" {
		t.Fatalf("Reveal(b) = %q, %v", got, err)
	}
}

func TestUpgradeEncryptionRunsOnceAndThenRefusesLegacyRows(t *testing.T) {
	db, baseURL := newTestDB(t)
	ctx := context.Background()
	rootKey := make([]byte, crypto.KeySize)
	users := storage.NewUserRepo(db, rootKey)
	secrets := storage.NewSecretRepo(db, rootKey)

	owner, err := users.CreateWithPassword(ctx, "legacy-owner", "x")
	if err != nil {
		t.Fatal(err)
	}
	// A row as written before migration 0007: no associated data.
	dek, _ := crypto.GenerateDEK()
	wrapped, dekNonce, _ := crypto.WrapDEK(rootKey, dek)
	ct, valueNonce, _ := crypto.Encrypt(dek, []byte("legacy-value"))
	enc := base64.StdEncoding.EncodeToString
	rawExec(t, baseURL, `INSERT INTO secrets
		(id, name, owner_type, owner_id, wrapped_dek, dek_nonce, ciphertext, value_nonce, key_version, aad_version, created_by, created_at, updated_at)
		VALUES (900, 'legacy', 'user', ?, ?, ?, ?, ?, 1, 0, ?, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`,
		owner.ID, enc(wrapped), enc(dekNonce), enc(ct), enc(valueNonce), owner.ID)

	if _, err := secrets.Reveal(ctx, 900); err == nil {
		t.Fatal("legacy row revealed before the upgrade")
	}
	n, err := secrets.UpgradeEncryption(ctx)
	if err != nil || n != 1 {
		t.Fatalf("UpgradeEncryption = %d, %v; want 1", n, err)
	}
	if got, err := secrets.Reveal(ctx, 900); err != nil || string(got) != "legacy-value" {
		t.Fatalf("Reveal after upgrade = %q, %v", got, err)
	}
	s, err := secrets.Get(ctx, 900)
	if err != nil || s.UpdatedAt.Format("2006-01-02") != "2026-01-01" {
		t.Fatalf("upgrade changed updated_at: %v, %v", s.UpdatedAt, err)
	}

	// After the upgrade has run, a legacy-format row is refused, not
	// upgraded again.
	rawExec(t, baseURL, `UPDATE secrets SET wrapped_dek = ?, dek_nonce = ?, ciphertext = ?, value_nonce = ?, aad_version = 0 WHERE id = 900`,
		enc(wrapped), enc(dekNonce), enc(ct), enc(valueNonce))
	if n, err := secrets.UpgradeEncryption(ctx); err != nil || n != 0 {
		t.Fatalf("second UpgradeEncryption = %d, %v; want 0", n, err)
	}
	if _, err := secrets.Reveal(ctx, 900); err == nil {
		t.Fatal("legacy row planted after the upgrade was revealed")
	}
}
