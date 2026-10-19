//go:build !windows

package contenthash

import (
	"io/fs"
	"path/filepath"
)

func (cc *cacheContext) walk(scanPath string, walkFunc fs.WalkDirFunc) error {
	return filepath.WalkDir(scanPath, walkFunc)
}

// This is a no-op on non-Windows
func enableProcessPrivileges() {}

// This is a no-op on non-Windows
func disableProcessPrivileges() {}
