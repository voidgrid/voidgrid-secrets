package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrKeyFileExists is returned by GenerateRootKeyFile when the target path
// already has a file. Overwriting an existing root key would make every
// secret encrypted under it permanently unrecoverable, so callers must
// remove or rotate it deliberately rather than have it silently replaced.
var ErrKeyFileExists = errors.New("crypto: root key file already exists")

// ErrKeyFilePermissions is returned by LoadRootKey when the key file is
// readable or writable by anyone other than its owner.
var ErrKeyFilePermissions = errors.New("crypto: root key file must not be group- or other-accessible (expected mode 0600)")

// GenerateRootKeyFile creates a new random root key at path, base64-encoded
// for operator readability, written with mode 0600. It refuses to run if a
// file already exists at path.
//
// The file is written to a temporary path in the same directory and then
// renamed into place, so a crash or interrupted write can never leave a
// partially written key file where the application might load it.
func GenerateRootKeyFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return ErrKeyFileExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("crypto: stat %s: %w", path, err)
	}

	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("crypto: generate root key: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".voidgrid-root-key-*.tmp")
	if err != nil {
		return fmt.Errorf("crypto: create temp key file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once the rename below succeeds

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("crypto: chmod temp key file: %w", err)
	}
	if _, err := tmp.WriteString(encoded + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("crypto: write temp key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("crypto: close temp key file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("crypto: rename key file into place: %w", err)
	}
	return nil
}

// LoadRootKey reads and decodes the root key at path, refusing to proceed
// if the file's permissions allow group or other access.
func LoadRootKey(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("crypto: stat root key file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, ErrKeyFilePermissions
	}

	raw, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied config, not untrusted user input
	if err != nil {
		return nil, fmt.Errorf("crypto: read root key file: %w", err)
	}

	encoded := string(raw)
	for len(encoded) > 0 && (encoded[len(encoded)-1] == '\n' || encoded[len(encoded)-1] == '\r') {
		encoded = encoded[:len(encoded)-1]
	}

	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode root key file: %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto: root key must be %d bytes, got %d", KeySize, len(key))
	}
	return key, nil
}
