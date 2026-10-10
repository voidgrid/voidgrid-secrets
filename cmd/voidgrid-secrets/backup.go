package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/voidgrid/voidgrid-secrets/internal/config"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// runBackup implements "voidgrid-secrets backup": a consistent copy of the
// database taken while the server runs. With -out it writes that file;
// without it, the copy goes to standard output, so from the host:
//
//	docker compose exec -T voidgrid-secrets voidgrid-secrets backup > voidgrid.db
//
// The root key is a separate file and is not included.
func runBackup(args []string) error {
	fset := flag.NewFlagSet("backup", flag.ContinueOnError)
	out := fset.String("out", "", "write the backup to this new file (default: standard output)")
	if err := fset.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if _, err := os.Stat(cfg.DBPath); err != nil {
		return fmt.Errorf("backup: no database at %s: %w", cfg.DBPath, err)
	}
	db, err := storage.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	defer db.Close()
	ctx := context.Background()

	if *out != "" {
		if err := db.BackupTo(ctx, *out); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
		fmt.Fprintf(os.Stderr, "backup written to %s\n", *out)
		return nil
	}

	if st, err := os.Stdout.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
		return errors.New("backup: refusing to write a database to a terminal - redirect to a file (> voidgrid.db) or use -out FILE")
	}
	dir, err := os.MkdirTemp("", "voidgrid-backup-")
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	tmp := filepath.Join(dir, "voidgrid.db")
	if err := db.BackupTo(ctx, tmp); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	f, err := os.Open(tmp) //nolint:gosec // a file this function just created in its own private temp directory
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := io.Copy(os.Stdout, f); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	return nil
}
