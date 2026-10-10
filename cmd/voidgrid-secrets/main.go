package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/voidgrid/voidgrid-secrets/internal/config"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/version"
)

func main() {
	var err error
	switch {
	case len(os.Args) > 1 && os.Args[1] == "keygen":
		err = runKeygen(os.Args[2:])
	case len(os.Args) > 1 && os.Args[1] == "run":
		err = runInject(os.Args[2:])
	case len(os.Args) > 1 && os.Args[1] == "agent":
		err = runAgent(os.Args[2:])
	case len(os.Args) > 1 && os.Args[1] == "backup":
		err = runBackup(os.Args[2:])
	case len(os.Args) > 1 && os.Args[1] == "recover":
		err = runRecover(os.Args[2:])
	case len(os.Args) > 1 && os.Args[1] == "version":
		fmt.Println(version.Version)
	default:
		err = run()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	return runServer(cfg)
}

// runKeygen implements the "voidgrid-secrets keygen" subcommand, which
// generates the root encryption key file with correct permissions.
func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	path := fs.String("path", "", "path to write the root key file (defaults to VOIDGRID_ROOT_KEY_PATH / its default)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	keyPath := *path
	if keyPath == "" {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		keyPath = cfg.RootKeyPath
	}

	if err := crypto.GenerateRootKeyFile(keyPath); err != nil {
		return err
	}

	fmt.Printf("generated root key: %s\n", keyPath)
	return nil
}
