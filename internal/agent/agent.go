// Package agent implements `voidgrid-secrets agent`: a sidecar that keeps
// each consumer's secrets as files on a shared in-memory volume, so the
// consumer needs no wrapper and no copy of this binary. Each target is one
// consumer: its own machine token (so its access is still scoped by that
// token's grants) and its own subdirectory, readable only by a group the
// consumer shares with the agent. Values are never logged.
package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/envname"
	"github.com/voidgrid/voidgrid-secrets/internal/runenv"
)

// DefaultReadyFile is created once every target has been written, for the
// container's healthcheck. It lives in the agent's own filesystem, not on
// the shared volume.
const DefaultReadyFile = "/tmp/voidgrid-agent-ready"

const (
	dirMode  os.FileMode = 0o750
	fileMode os.FileMode = 0o440
	// tmpPrefix marks a value being written; such files are never left
	// behind and never readable by the consumer's group.
	tmpPrefix = ".tmp-"
)

var targetNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// Target is one consumer: the subdirectory its files go in, the machine
// token whose grants decide what goes there, and the group that may read
// them.
type Target struct {
	Name      string
	TokenFile string
	GID       int
}

// ParseTarget parses NAME=TOKEN_FILE,gid=GID, e.g.
// "app=/run/secrets/app-token,gid=999".
func ParseTarget(s string) (Target, error) {
	name, rest, ok := strings.Cut(s, "=")
	if !ok {
		return Target{}, fmt.Errorf("target %q: want NAME=TOKEN_FILE,gid=GID", s)
	}
	if !targetNameRE.MatchString(name) {
		return Target{}, fmt.Errorf("target %q: name %q must be letters, digits, '_', '.' or '-', starting with a letter or digit", s, name)
	}
	parts := strings.Split(rest, ",")
	t := Target{Name: name, TokenFile: parts[0], GID: -1}
	if t.TokenFile == "" {
		return Target{}, fmt.Errorf("target %q: missing token file", s)
	}
	for _, opt := range parts[1:] {
		key, value, _ := strings.Cut(opt, "=")
		switch key {
		case "gid":
			gid, err := strconv.Atoi(value)
			if err != nil || gid < 0 {
				return Target{}, fmt.Errorf("target %q: gid %q is not a group ID", s, value)
			}
			t.GID = gid
		default:
			return Target{}, fmt.Errorf("target %q: unknown option %q (only gid is supported)", s, key)
		}
	}
	if t.GID < 0 {
		return Target{}, fmt.Errorf("target %q: gid=GID is required - the group the consumer reads its files as", s)
	}
	return t, nil
}

// Options configures Run.
type Options struct {
	// URL is the server's base URL, e.g. http://voidgrid-secrets:8443.
	URL     string
	OutDir  string
	Targets []Target
	// Interval is how often each target is re-checked after the first
	// write.
	Interval time.Duration
	// Timeout bounds how long the first write keeps retrying while the
	// server is unreachable or starting.
	Timeout    time.Duration
	RetryDelay time.Duration
	ReadyFile  string
	Client     *http.Client
	// Log receives progress messages (never values or tokens).
	Log io.Writer
	// IsMemFS reports whether a directory is in memory; see
	// runenv.IsMemoryFS.
	IsMemFS func(string) (bool, error)
	// Groups returns the agent's group IDs (primary and supplementary).
	Groups func() ([]int, error)
}

// ProcessGroups returns this process's primary and supplementary group IDs.
func ProcessGroups() ([]int, error) {
	groups, err := os.Getgroups()
	if err != nil {
		return nil, err
	}
	return append(groups, os.Getgid()), nil
}

// target is a Target plus what the agent last wrote for it.
type target struct {
	Target
	dir  string
	etag string
	// written maps each file's env name to a hash of the value written,
	// so unchanged values aren't rewritten.
	written map[string][sha256.Size]byte
	// failing is the last error logged for this target, so an outage is
	// logged once rather than on every poll.
	failing string
}

// Check validates opts without contacting the server: the output directory
// is in memory, the agent belongs to every target's group, and every token
// file is readable. Run calls it first, so a misconfigured agent never
// fetches anything.
func Check(o Options) error {
	if len(o.Targets) == 0 {
		return errors.New("no targets - give at least one --target NAME=TOKEN_FILE,gid=GID")
	}
	if o.Interval < time.Second {
		return fmt.Errorf("interval %s is too short (minimum 1s)", o.Interval)
	}
	if err := runenv.CheckFilesDir(o.OutDir, o.IsMemFS); err != nil {
		return err
	}
	groups, err := o.Groups()
	if err != nil {
		return fmt.Errorf("list this process's groups: %w", err)
	}
	seen := map[string]bool{}
	for _, t := range o.Targets {
		if seen[t.Name] {
			return fmt.Errorf("target %s is given more than once", t.Name)
		}
		seen[t.Name] = true
		if !slices.Contains(groups, t.GID) {
			return fmt.Errorf("target %s: the agent is not in group %d, so it can't give that group its files - add %d to the agent's group_add", t.Name, t.GID, t.GID)
		}
		if _, err := runenv.ReadTokenFile(t.TokenFile); err != nil {
			return fmt.Errorf("target %s: %w", t.Name, err)
		}
	}
	return nil
}

// Run writes every target's secrets, creates the ready file, then keeps
// them current until ctx is cancelled (which returns nil). It fails if the
// first write of any target can't complete within Timeout, or if the
// server rejects a target at startup.
func Run(ctx context.Context, o Options) error {
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	if o.ReadyFile == "" {
		o.ReadyFile = DefaultReadyFile
	}
	if o.RetryDelay <= 0 {
		o.RetryDelay = time.Second
	}
	if err := Check(o); err != nil {
		return err
	}
	// A ready file left from before a container restart would report
	// healthy before anything is written.
	if err := os.Remove(o.ReadyFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale ready file: %w", err)
	}
	defer func() { _ = os.Remove(o.ReadyFile) }()

	targets := make([]*target, 0, len(o.Targets))
	for _, t := range o.Targets {
		targets = append(targets, &target{Target: t, dir: filepath.Join(o.OutDir, t.Name)})
	}

	if err := initialSync(ctx, o, targets); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	if err := os.WriteFile(o.ReadyFile, nil, 0o600); err != nil {
		return fmt.Errorf("create ready file: %w", err)
	}
	logf(o.Log, "all %d target(s) written; checking every %s", len(targets), o.Interval)

	ticker := time.NewTicker(o.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		for _, t := range targets {
			poll(ctx, o, t)
		}
	}
}

// initialSync writes every target once, retrying unreachable/5xx until
// Timeout and failing at once on any other error.
func initialSync(ctx context.Context, o Options, targets []*target) error {
	deadline := time.Now().Add(o.Timeout)
	pending := slices.Clone(targets)
	for attempt := 1; ; attempt++ {
		var lastErr error
		remaining := pending[:0]
		for _, t := range pending {
			err := syncTarget(ctx, o, t)
			switch {
			case err == nil:
			case runenv.Retryable(err):
				lastErr = fmt.Errorf("target %s: %w", t.Name, err)
				remaining = append(remaining, t)
			default:
				return fmt.Errorf("target %s: %w", t.Name, err)
			}
		}
		pending = remaining
		if len(pending) == 0 {
			return nil
		}
		if time.Now().Add(o.RetryDelay).After(deadline) {
			return fmt.Errorf("gave up after %s: %w", o.Timeout, lastErr)
		}
		if attempt == 1 {
			logf(o.Log, "waiting for %s (%v)", o.URL, lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(o.RetryDelay):
		}
	}
}

// poll re-checks one target after startup. Errors don't stop the agent:
// while the server is unreachable the last values stay in place, and a
// rejected token (revoked or expired) removes that target's files.
func poll(ctx context.Context, o Options, t *target) {
	err := syncTarget(ctx, o, t)
	if err == nil {
		if t.failing != "" {
			logf(o.Log, "target %s: recovered", t.Name)
			t.failing = ""
		}
		return
	}
	if ctx.Err() != nil {
		return
	}

	var se *runenv.StatusError
	rejected := errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden)
	msg := err.Error()
	if rejected {
		if rmErr := clearTarget(t); rmErr != nil {
			msg += "; removing its files failed: " + rmErr.Error()
		} else {
			msg += "; its files have been removed"
		}
	} else {
		msg += "; keeping its last values"
	}
	if msg != t.failing {
		logf(o.Log, "target %s: %s", t.Name, msg)
		t.failing = msg
	}
}

// syncTarget fetches one target's secrets (conditionally, after the first time)
// and brings its directory in line with them.
func syncTarget(ctx context.Context, o Options, t *target) error {
	// Read the token every time, so replacing the token file takes effect
	// without restarting the agent.
	token, err := runenv.ReadTokenFile(t.TokenFile)
	if err != nil {
		return err
	}
	res, err := runenv.FetchOnce(ctx, o.Client, o.URL, token, t.etag)
	if err != nil {
		return err
	}
	if res.NotModified {
		return nil
	}
	if err := reconcile(o.Log, t, res.Secrets); err != nil {
		return err
	}
	t.etag = res.ETag
	return nil
}

// reconcile makes t's directory hold exactly secrets: changed or new
// values are written, files for anything no longer granted are removed.
func reconcile(log io.Writer, t *target, secrets []runenv.Secret) error {
	if err := ensureDir(t.dir, t.GID); err != nil {
		return err
	}
	if t.written == nil {
		t.written = map[string][sha256.Size]byte{}
	}

	want := map[string]bool{}
	for _, s := range secrets {
		if !envname.Valid(s.EnvName) {
			return fmt.Errorf("server sent an invalid environment variable name %q", s.EnvName)
		}
		want[s.EnvName] = true
		sum := sha256.Sum256([]byte(s.Value))
		if prev, ok := t.written[s.EnvName]; ok && prev == sum {
			continue
		}
		if err := writeFile(t.dir, s.EnvName, s.Value, t.GID); err != nil {
			return err
		}
		t.written[s.EnvName] = sum
		logf(log, "target %s: wrote %s", t.Name, s.EnvName)
	}

	entries, err := os.ReadDir(t.dir)
	if err != nil {
		return fmt.Errorf("list %s: %w", t.dir, err)
	}
	for _, e := range entries {
		if want[e.Name()] {
			continue
		}
		if err := os.Remove(filepath.Join(t.dir, e.Name())); err != nil {
			return fmt.Errorf("remove %s: %w", e.Name(), err)
		}
		delete(t.written, e.Name())
		if !strings.HasPrefix(e.Name(), tmpPrefix) {
			logf(log, "target %s: removed %s (no longer granted)", t.Name, e.Name())
		}
	}
	return nil
}

// clearTarget removes every file in t's directory but keeps the directory: the
// consumer's mount points at it, and recreating it would leave that mount
// pointing at a deleted directory.
func clearTarget(t *target) error {
	t.etag = ""
	t.written = nil
	entries, err := os.ReadDir(t.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.Remove(filepath.Join(t.dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// ensureDir creates dir (if needed) owned by gid with mode 0750: the
// consumer's group can list and read it, nobody else can.
func ensureDir(dir string, gid int) error {
	if err := os.Mkdir(dir, dirMode); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.Chown(dir, -1, gid); err != nil {
		return fmt.Errorf("set group of %s: %w", dir, err)
	}
	if err := os.Chmod(dir, dirMode); err != nil { //nolint:gosec // 0750 is intended: the consumer's group needs to list and enter it
		return fmt.Errorf("set mode of %s: %w", dir, err)
	}
	return nil
}

// writeFile replaces dir/name with value, mode 0440 and group gid. It
// writes a temporary file and renames it into place, so a reader sees
// either the old value or the new one, never part of one, and the
// temporary file is readable only by the agent until it's complete.
func writeFile(dir, name, value string, gid int) error {
	tmp := filepath.Join(dir, tmpPrefix+name)
	final := filepath.Join(dir, name)
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove leftover %s: %w", tmp, err)
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400) //nolint:gosec // dir is the operator's --out plus a validated target name, and name passed envname.Valid
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.WriteString(value); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Chown(-1, gid); err != nil {
		return fmt.Errorf("set group of %s: %w", tmp, err)
	}
	if err := f.Chmod(fileMode); err != nil {
		return fmt.Errorf("set mode of %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("rename into %s: %w", final, err)
	}
	ok = true
	return nil
}

func logf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, "voidgrid-secrets agent: "+format+"\n", args...)
}
