// Package runenv implements `voidgrid-secrets run`: fetch every secret a
// machine token may read from the API, put them into the environment (or
// into files on an in-memory mount), then replace this process with the
// real command. Values are never written to disk or printed.
package runenv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/envname"
)

// Secret is one secret from GET /api/v1/env.
type Secret struct {
	Name    string `json:"name"`
	EnvName string `json:"env_name"`
	Value   string `json:"value"`
}

// Var is one environment variable to set for the command.
type Var struct {
	Name  string
	Value string
}

// FetchOptions configures Fetch.
type FetchOptions struct {
	// URL is the server's base URL, e.g. http://voidgrid-secrets:8443.
	URL   string
	Token string
	// Timeout bounds how long Fetch keeps retrying while the server is
	// unreachable or not ready yet.
	Timeout    time.Duration
	RetryDelay time.Duration
	Client     *http.Client
	// Log receives progress messages (never values or the token).
	Log io.Writer
}

// Fetch returns every secret the token may read. It retries while the
// server is unreachable or answering 5xx (e.g. still starting, or setup
// not yet complete) until Timeout, and fails immediately on any 4xx
// (bad or revoked token, misconfigured grants).
func Fetch(ctx context.Context, o FetchOptions) ([]Secret, error) {
	client := o.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	delay := o.RetryDelay
	if delay <= 0 {
		delay = time.Second
	}
	logw := o.Log
	if logw == nil {
		logw = io.Discard
	}
	endpoint := strings.TrimRight(o.URL, "/") + "/api/v1/env"
	deadline := time.Now().Add(o.Timeout)

	for attempt := 1; ; attempt++ {
		secrets, retryable, err := fetchOnce(ctx, client, endpoint, o.Token)
		if err == nil {
			return secrets, nil
		}
		if !retryable || time.Now().Add(delay).After(deadline) {
			return nil, err
		}
		if attempt == 1 {
			_, _ = fmt.Fprintf(logw, "voidgrid-secrets run: waiting for %s (%v)\n", o.URL, err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}
}

func fetchOnce(ctx context.Context, client *http.Client, endpoint, token string) (secrets []Secret, retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("server unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		msg := errorDetail(resp.Body)
		err := fmt.Errorf("server returned %d: %s", resp.StatusCode, msg)
		return nil, resp.StatusCode >= 500, err
	}

	var body struct {
		Secrets []Secret `json:"secrets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, false, fmt.Errorf("decode response: %w", err)
	}
	return body.Secrets, false, nil
}

// errorDetail extracts the "detail" field of a huma error body, which
// never contains secret values.
func errorDetail(r io.Reader) string {
	var e struct {
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(io.LimitReader(r, 64<<10)).Decode(&e); err != nil || e.Detail == "" {
		return "no detail"
	}
	return e.Detail
}

// EnvVars maps each secret to NAME=value.
func EnvVars(secrets []Secret) ([]Var, error) {
	vars := make([]Var, 0, len(secrets))
	for _, s := range secrets {
		if !envname.Valid(s.EnvName) {
			return nil, fmt.Errorf("server sent an invalid environment variable name %q", s.EnvName)
		}
		vars = append(vars, Var{Name: s.EnvName, Value: s.Value})
	}
	return vars, nil
}

// CheckFilesDir returns an error unless dir is an in-memory filesystem
// (tmpfs or ramfs), as reported by isMemFS (see IsMemoryFS). Call it
// before fetching anything, so a misconfigured --files never pulls
// secrets from the server in the first place.
func CheckFilesDir(dir string, isMemFS func(string) (bool, error)) error {
	mem, err := isMemFS(dir)
	if err != nil {
		return fmt.Errorf("check --files directory %s: %w", dir, err)
	}
	if !mem {
		return fmt.Errorf("--files directory %s is not an in-memory filesystem (tmpfs/ramfs) - refusing to write secrets to disk", dir)
	}
	return nil
}

// FileVars writes each secret to dir/<NAME> (mode 0400) and maps it to
// NAME_FILE=<path>, for applications that read secrets from files. It
// re-checks dir with CheckFilesDir before writing anything.
func FileVars(dir string, secrets []Secret, isMemFS func(string) (bool, error)) ([]Var, error) {
	if err := CheckFilesDir(dir, isMemFS); err != nil {
		return nil, err
	}

	vars := make([]Var, 0, len(secrets))
	for _, s := range secrets {
		if !envname.Valid(s.EnvName) {
			return nil, fmt.Errorf("server sent an invalid environment variable name %q", s.EnvName)
		}
		path := filepath.Join(dir, s.EnvName)
		if err := writeSecretFile(path, s.Value); err != nil {
			return nil, err
		}
		vars = append(vars, Var{Name: s.EnvName + "_FILE", Value: path})
	}
	return vars, nil
}

func writeSecretFile(path, value string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400) //nolint:gosec // path is the operator's --files dir plus an envname.Valid name, so it can't escape that dir
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.WriteString(value); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

// Merge returns base with every variable named in strip removed and vars
// applied on top. overridden lists the names of vars that replaced a
// variable already present in base.
func Merge(base []string, vars []Var, strip []string) (env, overridden []string) {
	drop := map[string]bool{}
	for _, name := range strip {
		drop[name] = true
	}
	index := map[string]int{}
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		if drop[name] {
			continue
		}
		index[name] = len(env)
		env = append(env, kv)
	}
	for _, v := range vars {
		if i, ok := index[v.Name]; ok {
			env[i] = v.Name + "=" + v.Value
			overridden = append(overridden, v.Name)
			continue
		}
		index[v.Name] = len(env)
		env = append(env, v.Name+"="+v.Value)
	}
	return env, overridden
}

// Exec replaces the current process with argv, running with env. On
// success it never returns: the command keeps this process's PID, so
// signals and exit status behave as if it had been started directly.
func Exec(argv, env []string) error {
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return fmt.Errorf("find command %q: %w", argv[0], err)
	}
	return syscall.Exec(path, argv, env) //nolint:gosec // running the operator's own command is the whole point of `run`
}
