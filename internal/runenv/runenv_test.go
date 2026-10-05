package runenv_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/runenv"
)

const testToken = "vgs_test-token-value" //nolint:gosec // fake test fixture, not a real credential

func TestFetchRetriesUntilServerIsReady(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/env" || r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Errorf("unexpected request %s with auth %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"detail":"setup wizard must be completed first"}`)
			return
		}
		_, _ = io.WriteString(w, `{"secrets":[{"name":"db-password","env_name":"DB_PASSWORD","value":"s3cret"}]}`)
	}))
	defer srv.Close()

	secrets, err := runenv.Fetch(context.Background(), runenv.FetchOptions{
		URL: srv.URL, Token: testToken, Timeout: 5 * time.Second, RetryDelay: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if calls.Load() != 3 || len(secrets) != 1 || secrets[0].EnvName != "DB_PASSWORD" || secrets[0].Value != "s3cret" {
		t.Fatalf("got calls=%d secrets=%+v", calls.Load(), secrets)
	}
}

func TestFetchFailsImmediatelyOnRejectedToken(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"detail":"invalid or expired token"}`)
	}))
	defer srv.Close()

	_, err := runenv.Fetch(context.Background(), runenv.FetchOptions{
		URL: srv.URL, Token: testToken, Timeout: 5 * time.Second, RetryDelay: 10 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected an error for a rejected token")
	}
	if calls.Load() != 1 {
		t.Fatalf("got %d attempts, want 1 (4xx must not be retried)", calls.Load())
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatalf("error message leaks the token: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid or expired token") {
		t.Fatalf("error should carry the server's reason, got %v", err)
	}
}

func TestFetchGivesUpAfterTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	start := time.Now()
	_, err := runenv.Fetch(context.Background(), runenv.FetchOptions{
		URL: srv.URL, Token: testToken, Timeout: 100 * time.Millisecond, RetryDelay: 20 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected an error after the timeout")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("Fetch kept retrying far past its timeout (%v)", time.Since(start))
	}
}

func TestMergeStripsTokenVarsAndReportsOverrides(t *testing.T) {
	base := []string{"PATH=/bin", "VOIDGRID_TOKEN=" + testToken, "VOIDGRID_URL=http://x", "DB_PASSWORD=old"}
	vars := []runenv.Var{{Name: "DB_PASSWORD", Value: "new"}, {Name: "API_KEY", Value: "k"}}

	env, overridden := runenv.Merge(base, vars, []string{"VOIDGRID_TOKEN", "VOIDGRID_TOKEN_FILE", "VOIDGRID_URL"})

	joined := strings.Join(env, "\n")
	for _, want := range []string{"PATH=/bin", "DB_PASSWORD=new", "API_KEY=k"} {
		if !strings.Contains(joined, want) {
			t.Errorf("env missing %q: %v", want, env)
		}
	}
	for _, unwanted := range []string{"VOIDGRID_TOKEN", "VOIDGRID_URL", "DB_PASSWORD=old"} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("env should not contain %q: %v", unwanted, env)
		}
	}
	if len(env) != 3 || len(overridden) != 1 || overridden[0] != "DB_PASSWORD" {
		t.Fatalf("got env=%v overridden=%v", env, overridden)
	}
}

func TestFileVarsWritesReadOnlyFilesAndSetsFileVars(t *testing.T) {
	dir := t.TempDir()
	secrets := []runenv.Secret{{EnvName: "POSTGRES_PASSWORD", Value: "pg"}, {EnvName: "API_KEY", Value: "k"}}
	memFS := func(string) (bool, error) { return true, nil }

	vars, err := runenv.FileVars(dir, secrets, memFS)
	if err != nil {
		t.Fatalf("FileVars: %v", err)
	}
	if len(vars) != 2 || vars[0].Name != "POSTGRES_PASSWORD_FILE" || vars[0].Value != filepath.Join(dir, "POSTGRES_PASSWORD") {
		t.Fatalf("got vars %+v", vars)
	}
	info, err := os.Stat(vars[0].Value)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("file mode = %o, want 0400", info.Mode().Perm())
	}
	data, err := os.ReadFile(vars[0].Value)
	if err != nil || string(data) != "pg" {
		t.Fatalf("file content = %q, err %v", data, err)
	}

	// A second run (e.g. a container restart reusing the mount) replaces
	// the read-only files rather than failing.
	secrets[0].Value = "pg2"
	if _, err := runenv.FileVars(dir, secrets, memFS); err != nil {
		t.Fatalf("FileVars rerun: %v", err)
	}
	if data, _ := os.ReadFile(vars[0].Value); string(data) != "pg2" {
		t.Fatalf("rerun content = %q, want pg2", data)
	}
}

func TestFileVarsRefusesNonMemoryFilesystem(t *testing.T) {
	dir := t.TempDir()
	_, err := runenv.FileVars(dir, []runenv.Secret{{EnvName: "X", Value: "v"}}, func(string) (bool, error) { return false, nil })
	if err == nil || !strings.Contains(err.Error(), "not an in-memory filesystem") {
		t.Fatalf("got err %v, want a refusal", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("nothing should have been written, found %d entries", len(entries))
	}
}

func TestCheckFilesDir(t *testing.T) {
	if err := runenv.CheckFilesDir(t.TempDir(), func(string) (bool, error) { return true, nil }); err != nil {
		t.Errorf("memory filesystem rejected: %v", err)
	}
	if err := runenv.CheckFilesDir(t.TempDir(), func(string) (bool, error) { return false, nil }); err == nil {
		t.Error("non-memory filesystem accepted")
	}
}

func TestInvalidNamesFromServerAreRejected(t *testing.T) {
	bad := []runenv.Secret{{EnvName: "../../etc/passwd", Value: "v"}}
	if _, err := runenv.EnvVars(bad); err == nil {
		t.Error("EnvVars accepted an invalid name")
	}
	if _, err := runenv.FileVars(t.TempDir(), bad, func(string) (bool, error) { return true, nil }); err == nil {
		t.Error("FileVars accepted a path-traversal name")
	}
}
