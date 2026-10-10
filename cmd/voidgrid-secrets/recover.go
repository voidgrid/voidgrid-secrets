package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/voidgrid/voidgrid-secrets/internal/config"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// runRecover implements "voidgrid-secrets recover": the break-glass for
// when the account's password/authenticator and recovery codes are all
// lost. Run inside the server's container (docker exec), it prints a
// one-time code that starts an account reset at /recover. Only someone
// who can exec into the container can run it - the same person who can
// read the root key and the database anyway.
func runRecover(args []string) error {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	rootKey, err := crypto.LoadRootKey(cfg.RootKeyPath)
	if err != nil {
		return fmt.Errorf("recover: load root key: %w", err)
	}
	if err := storage.CheckLegacy(cfg.DBPath); err != nil {
		return fmt.Errorf("recover: %w", err)
	}
	db, err := storage.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("recover: open database: %w", err)
	}
	defer db.Close()

	ctx := context.Background()
	complete, err := storage.NewAuthConfigRepo(db, rootKey).IsComplete(ctx)
	if err != nil {
		return fmt.Errorf("recover: %w", err)
	}
	if !complete {
		return errors.New("recover: setup isn't complete - finish setup with the setup token in the server log instead")
	}

	auditRepo := storage.NewAuditRepo(db)
	svc := newRecoveryService(storage.NewUserRepo(db, rootKey), storage.NewResetRepo(db, rootKey),
		storage.NewRecoveryCodeRepo(db), storage.NewSessionRepo(db), auditRepo)
	code, expiresAt, err := svc.IssueBreakGlass(ctx)
	if err != nil {
		return fmt.Errorf("recover: %w", err)
	}

	fmt.Printf("recovery code: %s\n", code)
	fmt.Printf("Open /recover in a browser and enter it before %s UTC. It works once.\n", expiresAt.UTC().Format("2006-01-02 15:04"))
	return nil
}
