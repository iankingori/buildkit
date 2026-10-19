package contenthash

import (
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

type walkEntry struct {
	path  string
	isDir bool
	typ   fs.FileMode
}

func collect(t *testing.T, walk func(root string, fn fs.WalkDirFunc) error, root string) []walkEntry {
	t.Helper()
	var out []walkEntry
	err := walk(root, func(p string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		out = append(out, walkEntry{p, d.IsDir(), d.Type()})
		return nil
	})
	require.NoError(t, err)
	return out
}

func TestParallelWalkDirMatchesWalkDir(t *testing.T) {
	root := t.TempDir()
	r := rand.New(rand.NewSource(1))
	dirs := []string{root}
	for i := 0; i < 400; i++ {
		parent := dirs[r.Intn(len(dirs))]
		p := filepath.Join(parent, fmt.Sprintf("d%03d", i))
		require.NoError(t, os.Mkdir(p, 0o755))
		dirs = append(dirs, p)
	}
	for i := 0; i < 1500; i++ {
		parent := dirs[r.Intn(len(dirs))]
		require.NoError(t, os.WriteFile(filepath.Join(parent, fmt.Sprintf("f%04d", i)), []byte("x"), 0o644))
	}
	// empty dirs and a symlink (not followed by either walker)
	require.NoError(t, os.Mkdir(filepath.Join(root, "empty"), 0o755))
	if runtime.GOOS != "windows" {
		require.NoError(t, os.Symlink(dirs[1], filepath.Join(root, "link")))
	}

	want := collect(t, func(root string, fn fs.WalkDirFunc) error { return filepath.WalkDir(root, fn) }, root)
	for _, workers := range []int{1, 2, 8} {
		got := collect(t, func(root string, fn fs.WalkDirFunc) error { return parallelWalkDir(root, workers, nil, fn) }, root)
		require.Equal(t, want, got, "workers=%d", workers)
	}
}

func TestParallelWalkDirRootIsFileOrMissing(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o644))
	got := collect(t, func(root string, fn fs.WalkDirFunc) error { return parallelWalkDir(root, 4, nil, fn) }, f)
	require.Len(t, got, 1)
	require.False(t, got[0].isDir)

	var gotErr error
	err := parallelWalkDir(filepath.Join(dir, "missing"), 4, nil, func(p string, d fs.DirEntry, err error) error {
		gotErr = err
		return err
	})
	require.Error(t, err)
	require.ErrorIs(t, gotErr, os.ErrNotExist)
}
