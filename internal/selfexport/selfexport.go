// Package selfexport publishes the running executable into a directory so
// other containers can mount it read-only and use `voidgrid-secrets run`
// without a helper container or a custom image.
//
// The server calls it at start-up. The file is replaced atomically (write a
// temporary file beside it, then rename), so a consumer starting at that
// moment sees either the old binary or the new one, never half of one, and a
// process already running the old file keeps its own copy.
package selfexport

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// FileName is the name the executable is published under.
const FileName = "voidgrid-secrets"

// Result describes what Publish did.
type Result struct {
	// Path is the published file.
	Path string
	// Updated is false when the file already held this exact executable.
	Updated bool
}

// Publish copies the executable at src to dir/FileName with mode 0755,
// creating dir (mode 0755) if needed. If the destination already holds
// identical content nothing is written. dir is meant to be mounted into
// other containers, so it must be traversable and the file executable by
// any user.
func Publish(src, dir string) (Result, error) {
	dst := filepath.Join(dir, FileName)
	res := Result{Path: dst}

	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // consumers running as other users must be able to enter the directory; it holds only a public executable
		return res, fmt.Errorf("create %s: %w", dir, err)
	}

	same, err := sameContent(src, dst)
	if err != nil {
		return res, err
	}
	if same {
		if err := os.Chmod(dst, 0o755); err != nil { //nolint:gosec // see above: an executable other users must be able to run
			return res, fmt.Errorf("set mode of %s: %w", dst, err)
		}
		return res, nil
	}

	in, err := os.Open(src) //nolint:gosec // src is this process's own executable path
	if err != nil {
		return res, fmt.Errorf("open %s: %w", src, err)
	}
	defer func() { _ = in.Close() }()

	tmp, err := os.CreateTemp(dir, ".voidgrid-secrets-*")
	if err != nil {
		return res, fmt.Errorf("write into %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(tmpName) }

	if _, err := io.Copy(tmp, in); err != nil {
		cleanup()
		return res, fmt.Errorf("copy executable: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil { //nolint:gosec // an executable other users must be able to run
		cleanup()
		return res, fmt.Errorf("set mode: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return res, fmt.Errorf("sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return res, fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		return res, fmt.Errorf("replace %s: %w", dst, err)
	}
	res.Updated = true
	return res, nil
}

// sameContent reports whether dst exists and holds the same bytes as src.
func sameContent(src, dst string) (bool, error) {
	di, err := os.Stat(dst)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat %s: %w", dst, err)
	}
	si, err := os.Stat(src)
	if err != nil {
		return false, fmt.Errorf("stat %s: %w", src, err)
	}
	if !di.Mode().IsRegular() || di.Size() != si.Size() {
		return false, nil
	}
	a, err := fileHash(src)
	if err != nil {
		return false, err
	}
	b, err := fileHash(dst)
	if err != nil {
		return false, nil //nolint:nilerr // an unreadable destination is simply replaced
	}
	return a == b, nil
}

func fileHash(path string) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	f, err := os.Open(path) //nolint:gosec // paths are this package's own source and destination
	if err != nil {
		return sum, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, fmt.Errorf("read %s: %w", path, err)
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}
