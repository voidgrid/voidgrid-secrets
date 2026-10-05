//go:build linux

package runenv

import "syscall"

const (
	tmpfsMagic = 0x01021994
	ramfsMagic = 0x858458f6
)

// IsMemoryFS reports whether dir is on tmpfs or ramfs, i.e. whether files
// written there live only in memory.
func IsMemoryFS(dir string) (bool, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return false, err
	}
	switch uint32(st.Type) { //nolint:gosec // filesystem magic numbers fit in 32 bits
	case tmpfsMagic, ramfsMagic:
		return true, nil
	}
	return false, nil
}
