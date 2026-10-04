package crypto_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
)

func TestGenerateAndLoadRootKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "root.key")

	if err := crypto.GenerateRootKeyFile(path); err != nil {
		t.Fatalf("GenerateRootKeyFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file mode = %o, want 0600", perm)
	}

	key, err := crypto.LoadRootKey(path)
	if err != nil {
		t.Fatalf("LoadRootKey: %v", err)
	}
	if len(key) != crypto.KeySize {
		t.Fatalf("key length = %d, want %d", len(key), crypto.KeySize)
	}

	key2, err := crypto.LoadRootKey(path)
	if err != nil {
		t.Fatalf("LoadRootKey (second read): %v", err)
	}
	if !bytes.Equal(key, key2) {
		t.Fatal("loading the same key file twice produced different keys")
	}
}

func TestGenerateRootKeyFileRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "root.key")

	if err := crypto.GenerateRootKeyFile(path); err != nil {
		t.Fatalf("GenerateRootKeyFile: %v", err)
	}

	err := crypto.GenerateRootKeyFile(path)
	if !errors.Is(err, crypto.ErrKeyFileExists) {
		t.Fatalf("got err = %v, want ErrKeyFileExists", err)
	}
}

func TestLoadRootKeyRejectsLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "root.key")

	if err := crypto.GenerateRootKeyFile(path); err != nil {
		t.Fatalf("GenerateRootKeyFile: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // intentionally loosening perms to test rejection
		t.Fatalf("Chmod: %v", err)
	}

	_, err := crypto.LoadRootKey(path)
	if !errors.Is(err, crypto.ErrKeyFilePermissions) {
		t.Fatalf("got err = %v, want ErrKeyFilePermissions", err)
	}
}

func TestLoadRootKeyRejectsWrongLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "root.key")

	if err := os.WriteFile(path, []byte("dG9vc2hvcnQ=\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := crypto.LoadRootKey(path); err == nil {
		t.Fatal("expected LoadRootKey to reject a too-short key, got nil error")
	}
}
