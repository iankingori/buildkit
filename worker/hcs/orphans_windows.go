//go:build windows

package hcs

import (
	"context"
	"os"
	"path/filepath"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/pkg/cimfs"
	"github.com/containerd/containerd/v2/core/snapshots/storage"
	"github.com/moby/buildkit/util/bklog"
	"github.com/pkg/errors"
)

// removeOrphanSnapshots destroys snapshot directories (and CIM files) that the snapshotter
// metadata at root doesn't know about. They are left behind when the worker dies while a snapshot
// is being created, extracted or removed: the directory exists but the metadata transaction never
// committed, so the next snapshot is handed the same ID and then collides with the debris.
//
// It must run before the snapshotter opens its metadata, which is locked by one opener only.
func removeOrphanSnapshots(ctx context.Context, root string) error {
	dbPath := filepath.Join(root, "metadata.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil // nothing was ever created
	}
	ms, err := storage.NewMetaStore(dbPath)
	if err != nil {
		return errors.Wrap(err, "open snapshotter metadata")
	}
	var ids map[string]string
	err = ms.WithTransaction(ctx, false, func(ctx context.Context) (err error) {
		ids, err = storage.IDMap(ctx)
		return err
	})
	ms.Close()
	if err != nil {
		return errors.Wrap(err, "read snapshot IDs")
	}

	home := filepath.Join(root, "snapshots")
	entries, err := os.ReadDir(home)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	di := hcsshim.DriverInfo{HomeDir: home}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() {
			continue
		}
		if _, ok := ids[name]; ok {
			continue
		}
		bklog.G(ctx).Infof("removing orphaned snapshot directory %s (not in the snapshotter metadata)", name)
		if err := hcsshim.DestroyLayer(di, name); err != nil {
			// not a layer (a plain directory) or already partly gone
			if err := os.RemoveAll(filepath.Join(home, name)); err != nil {
				bklog.G(ctx).WithError(err).Warnf("failed to remove orphaned snapshot directory %s", name)
			}
		}
	}
	// CIM snapshotter: one set of files per snapshot ID.
	cimDir := filepath.Join(root, "cim-layers")
	cims, err := os.ReadDir(cimDir)
	if err != nil {
		return nil
	}
	for _, e := range cims {
		name := e.Name()
		if filepath.Ext(name) != ".cim" {
			continue
		}
		if _, ok := ids[name[:len(name)-len(".cim")]]; ok {
			continue
		}
		bklog.G(ctx).Infof("removing orphaned CIM %s", name)
		if err := cimfs.DestroyCim(ctx, filepath.Join(cimDir, name)); err != nil {
			bklog.G(ctx).WithError(err).Warnf("failed to remove orphaned CIM %s", name)
		}
	}
	return nil
}
