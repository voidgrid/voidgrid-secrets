//go:build linux

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/runenv"
)

const goodToken = "vgs_test-token" //nolint:gosec // fake test fixture, not a real credential

// fakeServer is a stand-in for GET /api/v1/env with a controllable answer.
type fakeServer struct {
	mu          sync.Mutex
	status      int // non-zero: answer with this error status
	secrets     []runenv.Secret
	etag        string
	fullFetches int
	notModified int
}

func (f *fakeServer) set(etag string, secrets ...runenv.Secret) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.etag, f.secrets, f.status = etag, secrets, 0
}

func (f *fakeServer) fail(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = status
}

func (f *fakeServer) counts() (full, notModified int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fullFetches, f.notModified
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status != 0 {
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(`{"detail":"nope"}`))
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+goodToken {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"bad token"}`))
		return
	}
	if r.Header.Get("If-None-Match") == f.etag {
		f.notModified++
		w.WriteHeader(http.StatusNotModified)
		return
	}
	f.fullFetches++
	w.Header().Set("ETag", f.etag)
	_ = json.NewEncoder(w).Encode(map[string]any{"secrets": f.secrets})
}

func sec(name, value string) runenv.Secret {
	return runenv.Secret{Name: strings.ToLower(name), EnvName: name, Value: value}
}

type harness struct {
	srv  *fakeServer
	http *httptest.Server
	opts Options
	log  *bytes.Buffer
	out  string
	gid  int
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	srv := &fakeServer{}
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte(goodToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	gid := os.Getgid()
	log := &bytes.Buffer{}
	return &harness{
		srv:  srv,
		http: hs,
		log:  log,
		out:  out,
		gid:  gid,
		opts: Options{
			URL:        hs.URL,
			OutDir:     out,
			Targets:    []Target{{Name: "app", TokenFile: tokenFile, GID: gid}},
			Interval:   time.Second,
			Timeout:    2 * time.Second,
			RetryDelay: 10 * time.Millisecond,
			ReadyFile:  filepath.Join(dir, "ready"),
			Client:     hs.Client(),
			Log:        log,
			IsMemFS:    func(string) (bool, error) { return true, nil },
			Groups:     func() ([]int, error) { return []int{gid}, nil },
		},
	}
}

func (h *harness) target() *target {
	t := h.opts.Targets[0]
	return &target{Target: t, dir: filepath.Join(h.out, t.Name)}
}

func readDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	got := map[string]string{}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // a test temp dir
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		got[e.Name()] = string(data)
	}
	return got
}

func assertFiles(t *testing.T, dir string, want map[string]string) {
	t.Helper()
	got := readDir(t, dir)
	if len(got) != len(want) {
		t.Fatalf("files = %v, want %v", keys(got), keys(want))
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("%s: got %q, want %q", name, got[name], value)
		}
	}
}

func keys(m map[string]string) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestParseTarget(t *testing.T) {
	got, err := ParseTarget("app=/run/secrets/app-token,gid=999")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if got != (Target{Name: "app", TokenFile: "/run/secrets/app-token", GID: 999}) { //nolint:gosec // a file path, not a credential
		t.Fatalf("got %+v", got)
	}

	for _, bad := range []string{
		"",
		"app",
		"app=",
		"app=/t",                 // gid required
		"app=/t,gid=",            // empty gid
		"app=/t,gid=-1",          // negative
		"app=/t,gid=abc",         // not a number
		"app=/t,gid=1,mode=0444", // unknown option
		"../x=/t,gid=1",          // path in name
		".hidden=/t,gid=1",
		"a/b=/t,gid=1",
	} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("ParseTarget(%q) succeeded, want an error", bad)
		}
	}
}

func TestCheckRejectsMisconfigurationBeforeFetching(t *testing.T) {
	h := newHarness(t)

	notMem := h.opts
	notMem.IsMemFS = func(string) (bool, error) { return false, nil }
	if err := Check(notMem); err == nil || !strings.Contains(err.Error(), "not an in-memory filesystem") {
		t.Errorf("disk-backed out dir: err = %v", err)
	}

	notMember := h.opts
	notMember.Groups = func() ([]int, error) { return []int{12345}, nil }
	if err := Check(notMember); err == nil || !strings.Contains(err.Error(), "group_add") {
		t.Errorf("gid not in agent's groups: err = %v", err)
	}

	noToken := h.opts
	noToken.Targets = []Target{{Name: "app", TokenFile: filepath.Join(t.TempDir(), "missing"), GID: h.gid}}
	if err := Check(noToken); err == nil {
		t.Error("missing token file: want an error")
	}

	dup := h.opts
	dup.Targets = append(dup.Targets, dup.Targets[0])
	if err := Check(dup); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Errorf("duplicate target: err = %v", err)
	}

	if full, nm := h.srv.counts(); full+nm != 0 {
		t.Fatalf("Check contacted the server (%d requests)", full+nm)
	}
}

func TestSyncWritesFilesWithGroupAndMode(t *testing.T) {
	h := newHarness(t)
	h.srv.set(`"v1"`, sec("DB_PASSWORD", "pg"), sec("API_KEY", "k"))
	tg := h.target()

	if err := syncTarget(context.Background(), h.opts, tg); err != nil {
		t.Fatalf("syncTarget: %v", err)
	}
	assertFiles(t, tg.dir, map[string]string{"DB_PASSWORD": "pg", "API_KEY": "k"})

	dirInfo, err := os.Stat(tg.dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != dirMode {
		t.Errorf("dir mode = %v, want %v", dirInfo.Mode().Perm(), dirMode)
	}
	for _, name := range []string{"DB_PASSWORD", "API_KEY"} {
		fi, err := os.Stat(filepath.Join(tg.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != fileMode {
			t.Errorf("%s mode = %v, want %v", name, fi.Mode().Perm(), fileMode)
		}
		if gid := int(fi.Sys().(*syscall.Stat_t).Gid); gid != h.gid {
			t.Errorf("%s group = %d, want %d", name, gid, h.gid)
		}
	}
	if strings.Contains(h.log.String(), "pg") {
		t.Fatal("a value was logged")
	}
}

func TestSyncSkipsUnchangedAndRewritesOnlyChangedValues(t *testing.T) {
	h := newHarness(t)
	h.srv.set(`"v1"`, sec("A", "1"), sec("B", "2"))
	tg := h.target()
	ctx := context.Background()

	if err := syncTarget(ctx, h.opts, tg); err != nil {
		t.Fatal(err)
	}
	// Same ETag: 304, nothing rewritten.
	h.log.Reset()
	if err := syncTarget(ctx, h.opts, tg); err != nil {
		t.Fatal(err)
	}
	if full, nm := h.srv.counts(); full != 1 || nm != 1 {
		t.Fatalf("full fetches = %d, 304s = %d; want 1 and 1", full, nm)
	}
	if h.log.Len() != 0 {
		t.Fatalf("unchanged poll logged: %s", h.log.String())
	}

	// B changes: only B is rewritten.
	h.srv.set(`"v2"`, sec("A", "1"), sec("B", "3"))
	if err := syncTarget(ctx, h.opts, tg); err != nil {
		t.Fatal(err)
	}
	assertFiles(t, tg.dir, map[string]string{"A": "1", "B": "3"})
	if log := h.log.String(); strings.Contains(log, "wrote A") || !strings.Contains(log, "wrote B") {
		t.Fatalf("expected only B rewritten, log: %s", log)
	}
}

func TestSyncRemovesUngrantedAndStrayFiles(t *testing.T) {
	h := newHarness(t)
	tg := h.target()
	// Left over from a previous agent run, including a half-written value.
	if err := os.Mkdir(tg.dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"OLD", tmpPrefix + "A"} {
		if err := os.WriteFile(filepath.Join(tg.dir, name), []byte("x"), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	h.srv.set(`"v1"`, sec("A", "1"), sec("B", "2"))
	ctx := context.Background()

	if err := syncTarget(ctx, h.opts, tg); err != nil {
		t.Fatal(err)
	}
	assertFiles(t, tg.dir, map[string]string{"A": "1", "B": "2"})

	h.srv.set(`"v2"`, sec("A", "1"))
	if err := syncTarget(ctx, h.opts, tg); err != nil {
		t.Fatal(err)
	}
	assertFiles(t, tg.dir, map[string]string{"A": "1"})
}

func TestPollRemovesFilesWhenTokenIsRejected(t *testing.T) {
	h := newHarness(t)
	h.srv.set(`"v1"`, sec("A", "1"))
	tg := h.target()
	ctx := context.Background()
	if err := syncTarget(ctx, h.opts, tg); err != nil {
		t.Fatal(err)
	}

	h.srv.fail(http.StatusUnauthorized)
	poll(ctx, h.opts, tg)
	poll(ctx, h.opts, tg)
	assertFiles(t, tg.dir, map[string]string{})
	if n := strings.Count(h.log.String(), "files have been removed"); n != 1 {
		t.Fatalf("rejection logged %d times, want once: %s", n, h.log.String())
	}

	// Access restored: files come back on the next poll.
	h.srv.set(`"v1"`, sec("A", "1"))
	poll(ctx, h.opts, tg)
	assertFiles(t, tg.dir, map[string]string{"A": "1"})
	if !strings.Contains(h.log.String(), "recovered") {
		t.Fatalf("recovery not logged: %s", h.log.String())
	}
}

func TestPollKeepsFilesWhileServerIsDown(t *testing.T) {
	h := newHarness(t)
	h.srv.set(`"v1"`, sec("A", "1"))
	tg := h.target()
	ctx := context.Background()
	if err := syncTarget(ctx, h.opts, tg); err != nil {
		t.Fatal(err)
	}

	h.srv.fail(http.StatusServiceUnavailable)
	poll(ctx, h.opts, tg)
	h.http.Close() // now unreachable
	poll(ctx, h.opts, tg)
	assertFiles(t, tg.dir, map[string]string{"A": "1"})
	if !strings.Contains(h.log.String(), "keeping its last values") {
		t.Fatalf("outage not logged: %s", h.log.String())
	}
}

func TestRunWritesReadyFileThenStopsCleanly(t *testing.T) {
	h := newHarness(t)
	h.srv.set(`"v1"`, sec("A", "1"))
	// A ready file from a previous container start must not count.
	if err := os.WriteFile(h.opts.ReadyFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, h.opts) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(h.out, "app", "A")); err == nil {
			if _, err := os.Stat(h.opts.ReadyFile); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("ready file never appeared; log: %s", h.log.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run after cancel: %v", err)
	}
	if _, err := os.Stat(h.opts.ReadyFile); !os.IsNotExist(err) {
		t.Fatalf("ready file still present after stop: %v", err)
	}
}

func TestRunFailsAtStartupWithoutReadyFile(t *testing.T) {
	t.Run("rejected token", func(t *testing.T) {
		h := newHarness(t)
		h.srv.fail(http.StatusUnauthorized)
		err := Run(context.Background(), h.opts)
		if err == nil || !strings.Contains(err.Error(), "401") {
			t.Fatalf("err = %v, want a 401", err)
		}
		if _, err := os.Stat(h.opts.ReadyFile); !os.IsNotExist(err) {
			t.Fatal("ready file created despite failure")
		}
	})
	t.Run("server never comes up", func(t *testing.T) {
		h := newHarness(t)
		h.http.Close()
		h.opts.Timeout = 100 * time.Millisecond
		err := Run(context.Background(), h.opts)
		if err == nil || !strings.Contains(err.Error(), "gave up") {
			t.Fatalf("err = %v, want a timeout", err)
		}
	})
}

func TestSyncSaysWhenTheTokenHasNoGrants(t *testing.T) {
	h := newHarness(t)
	tg := h.target()
	h.srv.set(`"v0"`)
	if err := syncTarget(context.Background(), h.opts, tg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.log.String(), "no readable secrets") {
		t.Fatalf("zero grants not reported: %s", h.log.String())
	}

	h.srv.set(`"v1"`, sec("A", "1"), sec("B", "2"))
	if err := syncTarget(context.Background(), h.opts, tg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.log.String(), "2 secret(s) granted") {
		t.Fatalf("grant count not reported: %s", h.log.String())
	}
}
