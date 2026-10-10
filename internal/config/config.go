// Package config loads voidgrid-secrets runtime configuration from
// environment variables, matching the docker-compose/automated deployment
// use case described in the project's design notes.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/voidgrid/voidgrid-secrets/internal/httpsec"
)

// Config holds runtime configuration for the voidgrid-secrets service.
type Config struct {
	// ListenAddr is the address the HTTP API/web server binds to.
	ListenAddr string

	// DBPath is the SQLite database file.
	DBPath string

	// RootKeyPath is the path to the 0600 root encryption key file used to
	// unseal the secret store on startup.
	RootKeyPath string

	// ExportDir is where the server publishes its own executable at start,
	// for other containers to mount and run `voidgrid-secrets run` from.
	// Empty disables it. Default: a "bin" directory beside the database.
	ExportDir string

	// HTTPAllowedNets lists networks (home LAN, Tailscale) whose sign-ins
	// over plain HTTP are allowed. Empty means Secure cookies everywhere.
	HTTPAllowedNets []netip.Prefix
}

// Load builds a Config from environment variables, applying defaults for
// anything unset.
func Load() (Config, error) {
	nets, err := httpsec.ParseNets(os.Getenv("VOIDGRID_HTTP_ALLOWED_NETS"))
	if err != nil {
		return Config{}, fmt.Errorf("VOIDGRID_HTTP_ALLOWED_NETS: %w", err)
	}
	cfg := Config{
		ListenAddr:      getEnv("VOIDGRID_LISTEN_ADDR", ":8780"),
		DBPath:          getEnv("VOIDGRID_DB_PATH", "/data/voidgrid.db"),
		RootKeyPath:     getEnv("VOIDGRID_ROOT_KEY_PATH", "/run/secrets/voidgrid-root-key"),
		HTTPAllowedNets: nets,
	}
	// An explicitly empty VOIDGRID_EXPORT_DIR switches the export off, so
	// this reads the variable directly instead of treating "" as unset.
	if v, set := os.LookupEnv("VOIDGRID_EXPORT_DIR"); set {
		cfg.ExportDir = v
	} else {
		cfg.ExportDir = filepath.Join(filepath.Dir(cfg.DBPath), "bin")
	}
	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
