// Package config loads voidgrid-secrets runtime configuration from
// environment variables, matching the docker-compose/automated deployment
// use case described in the project's design notes.
package config

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/voidgrid/voidgrid-secrets/internal/httpsec"
)

// Config holds runtime configuration for the voidgrid-secrets service.
type Config struct {
	// ListenAddr is the address the HTTP API/web server binds to.
	ListenAddr string

	// RqliteAddr is the base URL of the single-node rqlite instance.
	RqliteAddr string

	// RootKeyPath is the path to the 0600 root encryption key file used to
	// unseal the secret store on startup.
	RootKeyPath string

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
	return Config{
		ListenAddr:      getEnv("VOIDGRID_LISTEN_ADDR", ":8780"),
		RqliteAddr:      getEnv("VOIDGRID_RQLITE_ADDR", "http://127.0.0.1:4001"),
		RootKeyPath:     getEnv("VOIDGRID_ROOT_KEY_PATH", "/run/secrets/voidgrid-root-key"),
		HTTPAllowedNets: nets,
	}, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
