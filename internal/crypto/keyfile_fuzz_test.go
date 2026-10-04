package crypto_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
)

// FuzzLoadRootKey exercises the key-file parsing boundary: arbitrary file
// contents (malformed base64, wrong length after decoding, extra
// whitespace, binary garbage) must never panic, only return an error.
func FuzzLoadRootKey(f *testing.F) {
	validKey := make([]byte, crypto.KeySize)
	validEncoded := base64.StdEncoding.EncodeToString(validKey)

	f.Add([]byte(""))
	f.Add([]byte("not base64 at all!!"))
	f.Add([]byte("####"))
	f.Add([]byte(validEncoded))
	f.Add([]byte(validEncoded + "\n"))
	f.Add([]byte(validEncoded + "\r\n"))
	f.Add([]byte(validEncoded[:10]))
	f.Add([]byte(validEncoded + validEncoded))
	f.Add([]byte("   " + validEncoded + "   "))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "root.key")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		_, _ = crypto.LoadRootKey(path)
	})
}
