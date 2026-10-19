package contenthash

import (
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// parallelWalkDir walks the tree rooted at root like filepath.WalkDir (same order, same
// callbacks) but lists directories on several goroutines. Listing a directory is where the time
// goes on file systems with slow metadata access, such as the union mounts of Windows containers.
//
// withWorker, if not nil, wraps the body of every listing goroutine; Windows uses it to enable the
// backup privilege on each thread.
//
// The callback is always called from the calling goroutine, one entry at a time, so it needs no
// locking. Unlike filepath.WalkDir the callback must not return fs.SkipDir or fs.SkipAll.
func parallelWalkDir(root string, workers int, withWorker func(func() error) error, fn fs.WalkDirFunc) error {
	info, err := os.Lstat(root)
	if err != nil {
		return fn(root, nil, err)
	}
	rootEntry := fs.FileInfoToDirEntry(info)
	if !info.IsDir() {
		return fn(root, rootEntry, nil)
	}
	if workers < 1 {
		workers = 1
	}

	type listing struct {
		entries []fs.DirEntry
		err     error
	}
	var (
		mu       sync.Mutex
		cond     = sync.NewCond(&mu)
		stack    = []string{root} // directories waiting to be listed
		busy     int              // workers currently listing a directory
		listings = map[string]*listing{}
	)

	worker := func() error {
		for {
			mu.Lock()
			for len(stack) == 0 && busy > 0 {
				cond.Wait()
			}
			if len(stack) == 0 { // nothing left and nobody can add more
				mu.Unlock()
				cond.Broadcast()
				return nil
			}
			dir := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			busy++
			mu.Unlock()

			entries, err := os.ReadDir(dir)

			mu.Lock()
			listings[dir] = &listing{entries: entries, err: err}
			for _, e := range entries {
				if e.IsDir() {
					stack = append(stack, filepath.Join(dir, e.Name()))
				}
			}
			busy--
			mu.Unlock()
			cond.Broadcast()
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if withWorker != nil {
				_ = withWorker(worker)
				return
			}
			_ = worker()
		}()
	}
	wg.Wait()

	// Replay in filepath.WalkDir's order: an entry, then (for a directory) its sorted children.
	var walk func(path string, d fs.DirEntry) error
	walk = func(path string, d fs.DirEntry) error {
		if err := fn(path, d, nil); err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		l := listings[path]
		if l == nil {
			return nil
		}
		if l.err != nil {
			return fn(path, d, l.err)
		}
		for _, e := range l.entries {
			if err := walk(filepath.Join(path, e.Name()), e); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root, rootEntry)
}
