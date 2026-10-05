package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/agent"
	"github.com/voidgrid/voidgrid-secrets/internal/runenv"
)

// targetFlags collects repeated --target values.
type targetFlags []agent.Target

func (f *targetFlags) String() string {
	names := make([]string, 0, len(*f))
	for _, t := range *f {
		names = append(names, t.Name)
	}
	return strings.Join(names, ",")
}

func (f *targetFlags) Set(s string) error {
	t, err := agent.ParseTarget(s)
	if err != nil {
		return err
	}
	*f = append(*f, t)
	return nil
}

// runAgent implements "voidgrid-secrets agent": keep each target's secrets
// as files on a shared in-memory volume until stopped.
func runAgent(args []string) error {
	fset := flag.NewFlagSet("agent", flag.ContinueOnError)
	url := fset.String("url", os.Getenv("VOIDGRID_URL"), "voidgrid-secrets server URL (default $VOIDGRID_URL)")
	out := fset.String("out", "", "in-memory (tmpfs) directory to write each target's subdirectory into")
	var targets targetFlags
	fset.Var(&targets, "target", "NAME=TOKEN_FILE,gid=GID: write the secrets TOKEN_FILE's token may read to OUT/NAME, readable by group GID (repeatable)")
	interval := fset.Duration("interval", time.Minute, "how often to check for changed secrets")
	timeout := fset.Duration("timeout", 30*time.Second, "how long the first write keeps retrying while the server is unreachable or starting")
	readyFile := fset.String("ready-file", agent.DefaultReadyFile, "file created once every target has been written, for a healthcheck")
	fset.Usage = func() {
		_, _ = fmt.Fprintln(fset.Output(), "usage: voidgrid-secrets agent --url URL --out DIR --target NAME=TOKEN_FILE,gid=GID [--target ...]")
		fset.PrintDefaults()
	}
	if err := fset.Parse(args); err != nil {
		return err
	}
	if fset.NArg() > 0 {
		return fmt.Errorf("agent: unexpected arguments %q", fset.Args())
	}
	if *url == "" {
		return errors.New("agent: no server URL - set --url or VOIDGRID_URL")
	}
	if *out == "" {
		return errors.New("agent: no output directory - set --out")
	}

	// The agent is usually PID 1 in its container, which ignores signals
	// it has no handler for.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	err := agent.Run(ctx, agent.Options{
		URL:       *url,
		OutDir:    *out,
		Targets:   targets,
		Interval:  *interval,
		Timeout:   *timeout,
		ReadyFile: *readyFile,
		Log:       os.Stderr,
		IsMemFS:   runenv.IsMemoryFS,
		Groups:    agent.ProcessGroups,
	})
	if err != nil {
		return fmt.Errorf("agent: %w", err)
	}
	return nil
}
