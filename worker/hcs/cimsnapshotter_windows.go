//go:build windows

package hcs

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/security"
	"github.com/Microsoft/go-winio/vhd"
	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/computestorage"
	"github.com/Microsoft/hcsshim/pkg/cimfs"
	ocicimlayer "github.com/Microsoft/hcsshim/pkg/ociwclayer/cim"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/snapshots/storage"
	"github.com/containerd/continuity/fs"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

const cimScratchSize = 10 << 30

// cimSnapshotter stores read-only layers as forked CIMs (CimFS) and gives every writable layer an
// empty NTFS scratch VHDX. It follows containerd's cimfs snapshotter, with one addition: a
// build step's scratch can be committed. Its changes are exported as a layer tar and imported as
// a child CIM, so the cost of a commit depends on the size of the change only.
type cimSnapshotter struct {
	root   string
	ms     *storage.MetaStore
	cimDir string
	info   hcsshim.DriverInfo
}

func newCIMSnapshotter(root string) (*cimSnapshotter, error) {
	if !cimfs.IsCimFSSupported() {
		return nil, errors.New("this Windows build doesn't support CimFS")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	ms, err := storage.NewMetaStore(filepath.Join(root, "metadata.db"))
	if err != nil {
		return nil, err
	}
	s := &cimSnapshotter{
		root:   root,
		ms:     ms,
		cimDir: filepath.Join(root, "cim-layers"),
		info:   hcsshim.DriverInfo{HomeDir: filepath.Join(root, "snapshots")},
	}
	for _, d := range []string{s.info.HomeDir, s.cimDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			ms.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *cimSnapshotter) snapshotDir(id string) string { return filepath.Join(s.info.HomeDir, id) }
func (s *cimSnapshotter) cimPath(id string) string     { return filepath.Join(s.cimDir, id+".cim") }

func (s *cimSnapshotter) parentPaths(parentIDs []string) (layers, cims []string) {
	for _, id := range parentIDs {
		layers = append(layers, s.snapshotDir(id))
		cims = append(cims, s.cimPath(id))
	}
	return layers, cims
}

func isUnpackKey(key string) bool { return strings.Contains(key, snapshots.UnpackKeyPrefix) }

func (s *cimSnapshotter) Stat(ctx context.Context, key string) (info snapshots.Info, err error) {
	err = s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		_, info, _, err = storage.GetInfo(ctx, key)
		return err
	})
	return info, err
}

func (s *cimSnapshotter) Update(ctx context.Context, info snapshots.Info, fieldpaths ...string) (_ snapshots.Info, err error) {
	err = s.ms.WithTransaction(ctx, true, func(ctx context.Context) error {
		info, err = storage.UpdateInfo(ctx, info, fieldpaths...)
		return err
	})
	return info, err
}

func (s *cimSnapshotter) Usage(ctx context.Context, key string) (usage snapshots.Usage, err error) {
	var (
		id   string
		info snapshots.Info
	)
	err = s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		id, info, usage, err = storage.GetInfo(ctx, key)
		return err
	})
	if err != nil {
		return snapshots.Usage{}, err
	}
	if info.Kind == snapshots.KindActive {
		du, err := fs.DiskUsage(ctx, s.snapshotDir(id))
		if err != nil {
			return snapshots.Usage{}, err
		}
		usage = snapshots.Usage(du)
	}
	return usage, nil
}

func (s *cimSnapshotter) Walk(ctx context.Context, fn snapshots.WalkFunc, filters ...string) error {
	return s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		return storage.WalkInfo(ctx, fn, filters...)
	})
}

func (s *cimSnapshotter) Prepare(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	return s.createSnapshot(ctx, snapshots.KindActive, key, parent, opts)
}

func (s *cimSnapshotter) View(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	return s.createSnapshot(ctx, snapshots.KindView, key, parent, opts)
}

func (s *cimSnapshotter) Mounts(ctx context.Context, key string) (mounts []mount.Mount, err error) {
	err = s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		sn, err := storage.GetSnapshot(ctx, key)
		if err != nil {
			return errors.Wrap(err, "failed to get snapshot mount")
		}
		mounts = s.mounts(sn, key)
		return nil
	})
	return mounts, err
}

// isPlain reports whether the committed snapshot id is a plain directory (such as build context
// files) rather than a CIM layer.
func (s *cimSnapshotter) isPlain(id string) bool {
	_, err := os.Stat(s.cimPath(id))
	return os.IsNotExist(err)
}

// plain reports whether a snapshot is a plain directory: it has no parent layers, or its parent is
// itself a plain directory. Layers unpacked into a CIM are never plain.
func (s *cimSnapshotter) plain(sn storage.Snapshot, key string) bool {
	return !isUnpackKey(key) && (len(sn.ParentIDs) == 0 || s.isPlain(sn.ParentIDs[0]))
}

func (s *cimSnapshotter) createSnapshot(ctx context.Context, kind snapshots.Kind, key, parent string, opts []snapshots.Opt) (mounts []mount.Mount, err error) {
	err = s.ms.WithTransaction(ctx, true, func(ctx context.Context) (retErr error) {
		sn, err := storage.CreateSnapshot(ctx, kind, key, parent, opts...)
		if err != nil {
			return errors.Wrap(err, "failed to create snapshot")
		}
		dir := s.snapshotDir(sn.ID)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return errors.Wrapf(err, "failed to create snapshot dir %s", dir)
		}
		defer func() {
			if retErr != nil {
				os.RemoveAll(dir)
			}
		}()
		switch {
		case isUnpackKey(key):
			// A layer is unpacked into its CIM: no scratch needed.
		case s.plain(sn, key):
			// Files BuildKit writes directly (the Dockerfile, build context): a plain directory. A
			// build step can't run on top of one, so only read-only views of it make sense.
			if len(sn.ParentIDs) != 0 && kind != snapshots.KindView {
				return errors.New("a writable snapshot on top of a plain directory snapshot is not supported")
			}
		default:
			if err := createCIMScratch(dir); err != nil {
				return errors.Wrap(err, "failed to create scratch layer")
			}
		}
		mounts = s.mounts(sn, key)
		return nil
	})
	return mounts, err
}

func (s *cimSnapshotter) mounts(sn storage.Snapshot, key string) []mount.Mount {
	ro := "rw"
	if sn.Kind == snapshots.KindView {
		ro = "ro"
	}
	if s.plain(sn, key) {
		src := s.snapshotDir(sn.ID)
		if len(sn.ParentIDs) != 0 { // a view of a plain directory shows that directory
			src = s.snapshotDir(sn.ParentIDs[0])
		}
		return []mount.Mount{{Source: src, Type: "bind", Options: []string{ro, "rbind"}}}
	}
	// The CIM path is only used when a layer is unpacked into the snapshot; for a scratch it is ignored.
	options := []string{ro, mount.LayerCimPathFlag + s.cimPath(sn.ID)}
	if len(sn.ParentIDs) != 0 {
		layers, cims := s.parentPaths(sn.ParentIDs)
		layersJSON, _ := json.Marshal(layers)
		cimsJSON, _ := json.Marshal(cims)
		options = append(options, mount.ParentLayerPathsFlag+string(layersJSON), mount.ParentLayerCimPathsFlag+string(cimsJSON))
	}
	return []mount.Mount{{Source: s.snapshotDir(sn.ID), Type: mount.CimFSMountType, Options: options}}
}

// Commit makes the snapshot read-only. The layers that were unpacked into a CIM are already
// complete; for a build step's scratch the changes are written to a child CIM first.
func (s *cimSnapshotter) Commit(ctx context.Context, name, key string, opts ...snapshots.Opt) error {
	var (
		id string
		sn storage.Snapshot
	)
	err := s.ms.WithTransaction(ctx, false, func(ctx context.Context) (err error) {
		if id, _, _, err = storage.GetInfo(ctx, key); err != nil {
			return errors.Wrapf(err, "failed to get storage info for %s", key)
		}
		sn, err = storage.GetSnapshot(ctx, key)
		return err
	})
	if err != nil {
		return err
	}

	if !isUnpackKey(key) && !s.plain(sn, key) {
		// The expensive part runs outside the metadata transaction.
		layers, cims := s.parentPaths(sn.ParentIDs)
		if err := commitCIMScratch(ctx, s.info, s.snapshotDir(id), s.cimPath(id), layers, cims); err != nil {
			return errors.Wrapf(err, "failed to commit %s to a CIM layer", key)
		}
	}

	return s.ms.WithTransaction(ctx, true, func(ctx context.Context) error {
		du, err := fs.DiskUsage(ctx, s.snapshotDir(id))
		if err != nil {
			return errors.Wrap(err, "failed to collect disk usage of snapshot storage")
		}
		usage := snapshots.Usage(du)
		if cu, err := cimfs.GetCimUsage(ctx, s.cimPath(id)); err == nil {
			usage.Size += int64(cu)
		}
		if _, err := storage.CommitActive(ctx, key, name, usage, opts...); err != nil {
			return errors.Wrap(err, "failed to commit snapshot")
		}
		return nil
	})
}

func (s *cimSnapshotter) Remove(ctx context.Context, key string) error {
	var id, renamedID string
	err := s.ms.WithTransaction(ctx, false, func(ctx context.Context) (err error) {
		id, _, _, err = storage.GetInfo(ctx, key)
		return err
	})
	if err != nil {
		return errors.Wrapf(errdefs.ErrFailedPrecondition, "failed to get snapshot info: %s", err)
	}
	renamedID, err = s.preRemove(ctx, key)
	if err != nil {
		return errors.Wrap(errdefs.ErrFailedPrecondition, err.Error())
	}
	if err := cimfs.DestroyCim(ctx, s.cimPath(id)); err != nil {
		log.G(ctx).WithError(err).WithField("id", id).Warn("failed to clean up cim files")
	}
	// Anything left in the directory (the scratch) is removed the supported way.
	if err := hcsshim.DestroyLayer(s.info, renamedID); err != nil {
		// Plain directories aren't layers; remove them like any directory.
		if err := os.RemoveAll(s.snapshotDir(renamedID)); err != nil {
			log.G(ctx).WithError(err).WithField("id", renamedID).Warn("failed to remove snapshot directory")
		}
	}
	return nil
}

// preRemove removes the snapshot from the metadata store and renames its directory so that the
// caller can delete it at leisure; it returns the new directory name.
func (s *cimSnapshotter) preRemove(ctx context.Context, key string) (string, error) {
	var path, renamed, renamedID string
	var restore bool
	err := s.ms.WithTransaction(ctx, true, func(ctx context.Context) error {
		id, _, err := storage.Remove(ctx, key)
		if err != nil {
			return errors.Wrap(err, "failed to remove")
		}
		path = s.snapshotDir(id)
		renamedID = "rm-" + id
		renamed = s.snapshotDir(renamedID)
		if err := os.Rename(path, renamed); err != nil && !os.IsNotExist(err) {
			if !os.IsPermission(err) {
				return err
			}
			// A scratch left activated by a crash: deactivate it and try again.
			home, layerID := filepath.Split(path)
			if derr := hcsshim.DeactivateLayer(hcsshim.DriverInfo{HomeDir: home}, layerID); derr != nil && !os.IsNotExist(derr) {
				return errors.Wrapf(err, "failed to deactivate layer following failed rename: %s", derr)
			}
			if rerr := os.Rename(path, renamed); rerr != nil && !os.IsNotExist(rerr) {
				return errors.Wrapf(err, "second rename attempt following detach failed: %s", rerr)
			}
		}
		restore = true
		return nil
	})
	if err != nil {
		if restore {
			if err1 := os.Rename(renamed, path); err1 != nil {
				log.G(ctx).WithError(err1).WithField("path", renamed).Error("failed to rename after failed commit")
			}
		}
		return "", err
	}
	return renamedID, nil
}

func (s *cimSnapshotter) Close() error { return s.ms.Close() }

// createCIMScratch creates the empty, NTFS-formatted sandbox.vhdx that a container's writes go to.
func createCIMScratch(dir string) error {
	p := filepath.Join(dir, "sandbox.vhdx")
	h, err := vhd.CreateVirtualDisk(p, vhd.VirtualDiskAccessNone, vhd.CreateVirtualDiskFlagNone, &vhd.CreateVirtualDiskParameters{
		Version:  2,
		Version2: vhd.CreateVersion2{MaximumSize: cimScratchSize, BlockSizeInBytes: 1 << 20},
	})
	if err != nil {
		return errors.Wrap(err, "create vhd")
	}
	err = computestorage.FormatWritableLayerVhd(context.Background(), windows.Handle(h))
	syscall.CloseHandle(h)
	if err != nil {
		os.Remove(p)
		return errors.Wrap(err, "format vhd")
	}
	if err := security.GrantVmGroupAccess(p); err != nil {
		os.Remove(p)
		return errors.Wrap(err, "grant vm group access")
	}
	return nil
}

// commitCIMScratch writes the changes in the scratch layer in dir as a child CIM at cimPath, then
// removes the scratch.
func commitCIMScratch(ctx context.Context, info hcsshim.DriverInfo, dir, cimPath string, parentLayers, parentCims []string) error {
	if err := winio.EnableProcessPrivileges([]string{winio.SeBackupPrivilege, winio.SeRestorePrivilege}); err != nil {
		return errors.Wrap(err, "failed to enable privileges")
	}
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(exportCIMScratch(ctx, pw, info, filepath.Base(dir)))
	}()
	err := winio.RunWithPrivileges([]string{winio.SeSecurityPrivilege}, func() error {
		_, err := ocicimlayer.ImportCimLayerFromTar(ctx, pr, dir, cimPath, parentLayers, parentCims)
		return err
	})
	// Let the exporter finish if the importer stopped early.
	io.Copy(io.Discard, pr)
	if err != nil {
		return err
	}
	// The scratch has served its purpose and holds a second copy of the changes.
	if err := os.Remove(filepath.Join(dir, "sandbox.vhdx")); err != nil && !os.IsNotExist(err) {
		log.G(ctx).WithError(err).WithField("dir", dir).Warn("failed to remove committed scratch")
	}
	return nil
}
