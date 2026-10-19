package contenthash

import (
	"io/fs"
	"os"
	"strconv"
	"sync"

	"github.com/Microsoft/go-winio"
)

var (
	privileges        = []string{winio.SeBackupPrivilege}
	privilegeLock     sync.Mutex
	privilegeRefCount int
)

// walkWorkers is the number of goroutines that list directories while scanning. It can be
// overridden with BUILDKIT_CONTENTHASH_WALK_WORKERS (1 lists on a single goroutine).
func walkWorkers() int {
	if v, err := strconv.Atoi(os.Getenv("BUILDKIT_CONTENTHASH_WALK_WORKERS")); err == nil && v > 0 {
		return v
	}
	// Measured on Server Core: 1 lister ~4.5s, 2-4 listers ~3.3s, 8 ~4s, 16 ~6s (the union mount's
	// metadata path stops scaling).
	return 4
}

func (cc *cacheContext) walk(scanPath string, walkFunc fs.WalkDirFunc) error {
	// elevating the admin privileges to walk special files/directory
	// like `System Volume Information`, etc. See similar in #4994
	return winio.RunWithPrivileges(privileges, func() error {
		// Directory listing dominates the time on large images; do it on several threads, each
		// with the privileges enabled. The callback still runs on this goroutine.
		return parallelWalkDir(scanPath, walkWorkers(), func(f func() error) error {
			return winio.RunWithPrivileges(privileges, f)
		}, func(p string, d fs.DirEntry, err error) error {
			return walkFunc(p, d, err)
		})
	})
}

// Adds the SeBackupPrivilege to the process
// to be able to access some special files and directories.
func enableProcessPrivileges() {
	privilegeLock.Lock()
	defer privilegeLock.Unlock()

	if privilegeRefCount == 0 {
		_ = winio.EnableProcessPrivileges(privileges)
	}
	privilegeRefCount++
}

// Disables the SeBackupPrivilege on the process
// once the group of functions that needed it is complete.
func disableProcessPrivileges() {
	privilegeLock.Lock()
	defer privilegeLock.Unlock()

	if privilegeRefCount > 0 {
		privilegeRefCount--
		if privilegeRefCount == 0 {
			_ = winio.DisableProcessPrivileges(privileges)
		}
	}
}
