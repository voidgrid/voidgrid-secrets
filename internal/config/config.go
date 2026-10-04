// Package config loads voidgrid-secrets runtime configuration from
// environment variables, matching the docker-compose/automated deployment
// use case described in the project's design notes.
package config

import "os"

// Config holds runtime configuration for the voidgrid-secrets service.
type Config struct {
	// ListenAddr is the address the HTTP API/web server binds to.
	ListenAddr string

	// RqliteAddr is the base URL of the single-node rqlite instance.
	RqliteAddr string

	// RootKeyPath is the path to the 0600 root encryption key file used to
	// unseal the secret store on startup.
	RootKeyPath string
}

// Load builds a Config from environment variables, applying defaults for
// anything unset.
func Load() (Config, error) {
	return Config{
		ListenAddr:  getEnv("VOIDGRID_LISTEN_ADDR", ":8443"),
		RqliteAddr:  getEnv("VOIDGRID_RQLITE_ADDR", "http://127.0.0.1:4001"),
		RootKeyPath: getEnv("VOIDGRID_ROOT_KEY_PATH", "/run/secrets/voidgrid-root-key"),
	}, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
