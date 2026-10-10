package config_test

import (
	"path/filepath"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/config"
)

func TestExportDirDefaultsBesideTheDatabaseAndCanBeDisabled(t *testing.T) {
	t.Setenv("VOIDGRID_DB_PATH", "/var/lib/vgs/voidgrid.db")

	cfg, err := config.Load()
	if err != nil || cfg.ExportDir != filepath.Join("/var/lib/vgs", "bin") {
		t.Fatalf("default ExportDir = %q, %v; want a bin directory beside the database", cfg.ExportDir, err)
	}

	t.Setenv("VOIDGRID_EXPORT_DIR", "/elsewhere")
	if cfg, _ := config.Load(); cfg.ExportDir != "/elsewhere" {
		t.Fatalf("ExportDir = %q, want the explicit value", cfg.ExportDir)
	}

	t.Setenv("VOIDGRID_EXPORT_DIR", "")
	if cfg, _ := config.Load(); cfg.ExportDir != "" {
		t.Fatalf("ExportDir = %q, want empty (export disabled) when the variable is set to empty", cfg.ExportDir)
	}
}
