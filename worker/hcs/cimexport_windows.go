//go:build windows

package hcs

import (
	"archive/tar"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/backuptar"
	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/pkg/ociwclayer"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

// This is a copy of hcsshim's pkg/ociwclayer/cim ExportScratchToTar (feature/runhcs-cim branch),
// on the public hcsshim API. It should move upstream into hcsshim.

const (
	scratchTombstonesFile = `Windows\container_tombstones.json`
	scratchHivesDir       = `WcSandboxState\Hives`
	scratchSystemVolInfo  = `System Volume Information`
	scratchSandboxState   = `WcSandboxState`
)

// fixedFiletime (2000-01-01) stamps the synthetic "Files" and "Hives" directory entries, so that
// exporting the same scratch twice gives the same tar.
var fixedFiletime = windows.Filetime{LowDateTime: 0xD53E8000, HighDateTime: 0x01BF53EB}

// exportCIMScratch writes the changes a container made in the CIM scratch layer `id` below
// info.HomeDir as an OCI layer tar: file changes under "Files/", deletions as whiteouts and the
// registry hive deltas under "Hives/". The container must have released the scratch.
func exportCIMScratch(ctx context.Context, w io.Writer, info hcsshim.DriverInfo, id string) (retErr error) {
	if err := hcsshim.ActivateLayer(info, id); err != nil {
		return errors.Wrap(err, "activate scratch layer")
	}
	defer func() {
		if err := hcsshim.DeactivateLayer(info, id); err != nil && retErr == nil {
			retErr = errors.Wrap(err, "deactivate scratch layer")
		}
	}()
	vol, err := hcsshim.GetLayerMountPath(info, id)
	if err != nil {
		return errors.Wrap(err, "get scratch mount path")
	}
	root := strings.TrimSuffix(vol, `\`) + `\`

	tombstones, err := readScratchTombstones(root)
	if err != nil {
		return err
	}

	t := tar.NewWriter(w)
	if err := writeSyntheticDir(t, "Files"); err != nil {
		return err
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel := strings.TrimPrefix(p, root)
		switch {
		case strings.EqualFold(rel, scratchSystemVolInfo), strings.EqualFold(rel, scratchSandboxState):
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		case strings.EqualFold(rel, scratchTombstonesFile):
			return nil
		}
		return writeScratchEntry(t, p, "Files/"+filepath.ToSlash(rel))
	})
	if err != nil {
		return err
	}
	for _, ts := range tombstones {
		ts = filepath.ToSlash(ts)
		dir, base := "", ts
		if i := strings.LastIndex(ts, "/"); i >= 0 {
			dir, base = ts[:i+1], ts[i+1:]
		}
		if err := t.WriteHeader(&tar.Header{Name: "Files/" + dir + ociwclayer.WhiteoutPrefix + base}); err != nil {
			return err
		}
	}

	if err := writeSyntheticDir(t, "Hives"); err != nil {
		return err
	}
	hives, err := os.ReadDir(filepath.Join(root, scratchHivesDir))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, h := range hives {
		// the registry transaction logs don't belong in the layer, only the deltas do
		if h.IsDir() || !strings.HasSuffix(strings.ToLower(h.Name()), "_delta") {
			continue
		}
		if err := writeScratchEntry(t, filepath.Join(root, scratchHivesDir, h.Name()), "Hives/"+h.Name()); err != nil {
			return err
		}
	}
	return t.Close()
}

// readScratchTombstones returns the layer-relative paths of the files the container deleted.
func readScratchTombstones(root string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(root, scratchTombstonesFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Wrap(err, "read tombstones")
	}
	var doc struct {
		TombstonePaths [][]json.RawMessage `json:"tombstonePaths"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, errors.Wrap(err, "parse tombstones")
	}
	var out []string
	for _, e := range doc.TombstonePaths {
		if len(e) == 0 {
			continue
		}
		var path string
		if err := json.Unmarshal(e[0], &path); err != nil {
			return nil, errors.Wrap(err, "parse tombstone path")
		}
		out = append(out, path)
	}
	return out, nil
}

func writeSyntheticDir(t *tar.Writer, name string) error {
	fi := &winio.FileBasicInfo{
		CreationTime:   fixedFiletime,
		LastAccessTime: fixedFiletime,
		LastWriteTime:  fixedFiletime,
		ChangeTime:     fixedFiletime,
		FileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY,
	}
	return t.WriteHeader(backuptar.BasicInfoHeader(name, 0, fi))
}

// writeScratchEntry adds one file or directory of the activated scratch volume to the tar.
func writeScratchEntry(t *tar.Writer, osPath, name string) error {
	f, err := winio.OpenForBackup(osPath, syscall.GENERIC_READ|winio.ACCESS_SYSTEM_SECURITY, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, syscall.OPEN_EXISTING)
	if err != nil {
		return errors.Wrapf(err, "open %s", osPath)
	}
	defer f.Close()
	fi, err := winio.GetFileBasicInfo(f)
	if err != nil {
		return errors.Wrapf(err, "get file info %s", osPath)
	}
	// Reading a file updates its access time, which would make the tar differ between exports.
	fi.LastAccessTime = fi.LastWriteTime
	st, err := f.Stat()
	if err != nil {
		return errors.Wrapf(err, "stat %s", osPath)
	}
	size := int64(0)
	if !st.IsDir() {
		size = st.Size()
	}
	r := winio.NewBackupFileReader(f, true)
	defer r.Close()
	return backuptar.WriteTarFileFromBackupStream(t, r, name, size, fi)
}
