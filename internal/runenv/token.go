package runenv

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// DefaultTokenFile is where a compose `secrets:` entry named
// voidgrid-token is mounted.
const DefaultTokenFile = "/run/secrets/voidgrid-token" //nolint:gosec // a file path, not a credential

// LoadToken reads the machine token from flagPath if set, else
// $VOIDGRID_TOKEN_FILE, else DefaultTokenFile, falling back to
// $VOIDGRID_TOKEN only when no file was named explicitly and the default
// file doesn't exist.
func LoadToken(flagPath string) (string, error) {
	path := flagPath
	if path == "" {
		path = os.Getenv("VOIDGRID_TOKEN_FILE")
	}
	if path != "" {
		return ReadTokenFile(path)
	}

	token, err := ReadTokenFile(DefaultTokenFile)
	if errors.Is(err, fs.ErrNotExist) {
		if token := strings.TrimSpace(os.Getenv("VOIDGRID_TOKEN")); token != "" {
			return token, nil
		}
		return "", fmt.Errorf("no machine token - mount one at %s, or set --token-file, VOIDGRID_TOKEN_FILE, or VOIDGRID_TOKEN", DefaultTokenFile)
	}
	return token, err
}

// ReadTokenFile reads a machine token from path, trimming surrounding
// whitespace. An empty file is an error.
func ReadTokenFile(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // reading the operator-configured token file is the point
	if err != nil {
		return "", fmt.Errorf("read token file %s: %w", path, err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("token file %s is empty", path)
	}
	return token, nil
}
