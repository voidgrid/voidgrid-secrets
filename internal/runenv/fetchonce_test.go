package runenv_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/runenv"
)

func TestFetchOnceSendsETagAndReportsNotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"e1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"e1"`)
		_, _ = w.Write([]byte(`{"secrets":[{"name":"a","env_name":"A","value":"1"}]}`))
	}))
	defer srv.Close()
	ctx := context.Background()

	res, err := runenv.FetchOnce(ctx, srv.Client(), srv.URL, "tok", "")
	if err != nil || res.NotModified || res.ETag != `"e1"` || len(res.Secrets) != 1 {
		t.Fatalf("first fetch: %+v, %v", res, err)
	}
	res, err = runenv.FetchOnce(ctx, srv.Client(), srv.URL, "tok", res.ETag)
	if err != nil || !res.NotModified || len(res.Secrets) != 0 || res.ETag != `"e1"` {
		t.Fatalf("conditional fetch: %+v, %v", res, err)
	}
}

func TestRetryableClassifiesErrors(t *testing.T) {
	status := func(code int) error {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
		}))
		defer srv.Close()
		_, err := runenv.FetchOnce(context.Background(), srv.Client(), srv.URL, "tok", "")
		return err
	}
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	_, unreachable := runenv.FetchOnce(context.Background(), closed.Client(), closed.URL, "tok", "")

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"503", status(http.StatusServiceUnavailable), true},
		{"unreachable", unreachable, true},
		{"401", status(http.StatusUnauthorized), false},
		{"409", status(http.StatusConflict), false},
		{"other error", errors.New("token file missing"), false},
	}
	for _, c := range cases {
		if c.err == nil {
			t.Fatalf("%s: no error", c.name)
		}
		if got := runenv.Retryable(c.err); got != c.want {
			t.Errorf("%s: Retryable = %v, want %v (%v)", c.name, got, c.want, c.err)
		}
	}
}

func TestLoadTokenPrecedence(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "tok")
	if err := os.WriteFile(file, []byte(" from-file \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VOIDGRID_TOKEN", "from-env")
	t.Setenv("VOIDGRID_TOKEN_FILE", "")

	if got, err := runenv.LoadToken(file); err != nil || got != "from-file" {
		t.Fatalf("explicit file: %q, %v", got, err)
	}
	// An explicitly named missing file is an error, not a fallback to the
	// environment variable.
	if _, err := runenv.LoadToken(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing explicit file: want an error")
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runenv.LoadToken(empty); err == nil {
		t.Fatal("empty file: want an error")
	}
}
