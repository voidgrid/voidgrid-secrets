//go:build !linux

package runenv

import "errors"

// IsMemoryFS can't verify the filesystem type off Linux, so file mode is
// refused rather than risk writing secrets to disk.
func IsMemoryFS(string) (bool, error) {
	return false, errors.New("--files is only supported on Linux")
}
