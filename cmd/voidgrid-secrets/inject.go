package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/runenv"
)

// stripFromChild are this command's own settings: they're removed from the
// environment the wrapped command sees, so the token doesn't leak into it.
var stripFromChild = []string{"VOIDGRID_TOKEN", "VOIDGRID_TOKEN_FILE", "VOIDGRID_URL"}

// runInject implements "voidgrid-secrets run": fetch this machine token's
// secrets and exec the given command with them injected.
func runInject(args []string) error {
	fset := flag.NewFlagSet("run", flag.ContinueOnError)
	url := fset.String("url", os.Getenv("VOIDGRID_URL"), "voidgrid-secrets server URL (default $VOIDGRID_URL)")
	tokenFile := fset.String("token-file", "", "file holding the machine token (default $VOIDGRID_TOKEN_FILE, then "+runenv.DefaultTokenFile+", then $VOIDGRID_TOKEN)")
	filesDir := fset.String("files", "", "write each secret to a file in this in-memory (tmpfs) directory and set NAME_FILE instead of NAME")
	timeout := fset.Duration("timeout", 30*time.Second, "how long to keep retrying while the server is unreachable or starting")
	fset.Usage = func() {
		_, _ = fmt.Fprintln(fset.Output(), "usage: voidgrid-secrets run [flags] -- command [args...]")
		fset.PrintDefaults()
	}
	if err := fset.Parse(args); err != nil {
		return err
	}

	command := fset.Args()
	if len(command) == 0 {
		return errors.New("run: no command given - usage: voidgrid-secrets run [flags] -- command [args...]")
	}
	if *url == "" {
		return errors.New("run: no server URL - set --url or VOIDGRID_URL")
	}
	if *filesDir != "" {
		if err := runenv.CheckFilesDir(*filesDir, runenv.IsMemoryFS); err != nil {
			return fmt.Errorf("run: %w", err)
		}
	}
	token, err := runenv.LoadToken(*tokenFile)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}

	secrets, err := runenv.Fetch(context.Background(), runenv.FetchOptions{
		URL:     *url,
		Token:   token,
		Timeout: *timeout,
		Log:     os.Stderr,
	})
	if err != nil {
		return fmt.Errorf("run: fetching secrets: %w", err)
	}

	var vars []runenv.Var
	if *filesDir != "" {
		vars, err = runenv.FileVars(*filesDir, secrets, runenv.IsMemoryFS)
	} else {
		vars, err = runenv.EnvVars(secrets)
	}
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}

	fmt.Fprintf(os.Stderr, "voidgrid-secrets run: injecting %s\n", runenv.Summary(vars))
	env, overridden := runenv.Merge(os.Environ(), vars, stripFromChild)
	for _, name := range overridden {
		fmt.Fprintf(os.Stderr, "voidgrid-secrets run: %s from voidgrid-secrets replaces an existing environment variable\n", name)
	}

	if err := runenv.Exec(command, env); err != nil {
		return fmt.Errorf("run: %w", err)
	}
	return nil
}
