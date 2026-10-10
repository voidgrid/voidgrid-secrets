package selfexport_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/selfexport"
)

func writeSrc(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "src-binary")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPublishCopiesAnExecutableAnyUserCanRun(t *testing.T) {
	src := writeSrc(t, "v1 contents")
	dir := filepath.Join(t.TempDir(), "nested", "bin")

	res, err := selfexport.Publish(src, dir)
	if err != nil || !res.Updated {
		t.Fatalf("Publish = %+v, %v", res, err)
	}
	if res.Path != filepath.Join(dir, selfexport.FileName) {
		t.Fatalf("Path = %q", res.Path)
	}
	got, err := os.ReadFile(res.Path)
	if err != nil || string(got) != "v1 contents" {
		t.Fatalf("published content = %q, %v", got, err)
	}
	if st, _ := os.Stat(res.Path); st.Mode().Perm() != 0o755 {
		t.Fatalf("file mode = %v, want 0755", st.Mode().Perm())
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o755 {
		t.Fatalf("directory mode = %v, want 0755", st.Mode().Perm())
	}
}

func TestPublishIsANoOpWhenIdenticalAndReplacesWhenDifferent(t *testing.T) {
	dir := t.TempDir()
	src := writeSrc(t, "same")
	first, err := selfexport.Publish(src, dir)
	if err != nil || !first.Updated {
		t.Fatal(first, err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(first.Path, old, old); err != nil {
		t.Fatal(err)
	}

	again, err := selfexport.Publish(src, dir)
	if err != nil || again.Updated {
		t.Fatalf("identical content: %+v, %v; want no update", again, err)
	}
	if st, _ := os.Stat(first.Path); st.ModTime().After(old.Add(time.Minute)) {
		t.Fatalf("an unchanged file was rewritten (mtime %v, was set to %v)", st.ModTime(), old)
	}

	// Same size, different bytes: must still be detected.
	if err := os.WriteFile(src, []byte("diff"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := selfexport.Publish(src, dir)
	if err != nil || !res.Updated {
		t.Fatalf("changed content: %+v, %v; want an update", res, err)
	}
	if got, _ := os.ReadFile(res.Path); string(got) != "diff" {
		t.Fatalf("content = %q", got)
	}
}

func TestPublishReplacesAtomicallyAndLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	src := writeSrc(t, "v1")
	res, _ := selfexport.Publish(src, dir)

	// A reader that opened the old file keeps seeing the old bytes after a replace.
	held, err := os.Open(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	if err := os.WriteFile(src, []byte("v2-longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := selfexport.Publish(src, dir); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, _ := held.Read(buf)
	if string(buf[:n]) != "v1" {
		t.Fatalf("an open reader saw %q after the replace, want the old file", buf[:n])
	}
	if got, _ := os.ReadFile(res.Path); string(got) != "v2-longer" {
		t.Fatalf("new content = %q", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory holds %v, want only the published file", names)
	}
}

func TestPublishFixesAWrongModeAndReportsUnwritableDirs(t *testing.T) {
	dir := t.TempDir()
	src := writeSrc(t, "v1")
	res, _ := selfexport.Publish(src, dir)
	if err := os.Chmod(res.Path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := selfexport.Publish(src, dir); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(res.Path); st.Mode().Perm() != 0o755 {
		t.Fatalf("mode after republish = %v, want 0755", st.Mode().Perm())
	}

	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	ro := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(ro, 0o500); err != nil { //nolint:gosec // a read-only temp dir for the test
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(ro, 0o700) }() //nolint:gosec // restore so cleanup can remove it
	if _, err := selfexport.Publish(src, ro); err == nil {
		t.Fatal("expected an error for an unwritable directory")
	}
	if _, err := selfexport.Publish(filepath.Join(t.TempDir(), "missing"), t.TempDir()); err == nil {
		t.Fatal("a missing source executable must be an error")
	}
}
