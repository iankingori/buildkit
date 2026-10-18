//go:build windows

// Package hcs is a BuildKit worker for Windows that needs no container daemon: layers are stored
// with containerd's Windows snapshotter in-process and build steps run through the runhcs executor.
package hcs

import (
	"context"
	"maps"
	"os"
	"path/filepath"

	ctdmetadata "github.com/containerd/containerd/v2/core/metadata"
	ctdsnapshot "github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/plugins/content/local"
	windowsdiff "github.com/containerd/containerd/v2/plugins/diff/windows"
	windowssnapshot "github.com/containerd/containerd/v2/plugins/snapshots/windows"
	"github.com/containerd/platforms"
	"github.com/moby/buildkit/cache/metadata"
	"github.com/moby/buildkit/executor/oci"
	"github.com/moby/buildkit/executor/runhcsexecutor"
	containerdsnapshot "github.com/moby/buildkit/snapshot/containerd"
	"github.com/moby/buildkit/util/db/boltutil"
	"github.com/moby/buildkit/util/db/compaction"
	"github.com/moby/buildkit/util/leaseutil"
	"github.com/moby/buildkit/util/network/netproviders"
	"github.com/moby/buildkit/worker/base"
	wlabel "github.com/moby/buildkit/worker/label"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sync/semaphore"
)

// Snapshotter names. "windows" keeps layers in the classic Windows layer format; "cim" stores them as
// forked CIMs (CimFS), which makes committing a build step cheap.
const (
	WindowsSnapshotter = "windows"
	CIMSnapshotter     = "cim"
)

// NewWorkerOpt creates a WorkerOpt for the daemon-less Windows worker. snapshotterName is
// WindowsSnapshotter (the default) or CIMSnapshotter.
func NewWorkerOpt(root string, labels map[string]string, nopt netproviders.Opt, dns *oci.DNSConfig, binary, snapshotterName string, parallelismSem *semaphore.Weighted, policies ...compaction.Config) (base.WorkerOpt, error) {
	var opt base.WorkerOpt
	if snapshotterName == "" {
		snapshotterName = WindowsSnapshotter
	}
	if snapshotterName != WindowsSnapshotter && snapshotterName != CIMSnapshotter {
		return opt, errors.Errorf("unknown snapshotter %q (use %q or %q)", snapshotterName, WindowsSnapshotter, CIMSnapshotter)
	}
	root = filepath.Join(root, "hcs-"+snapshotterName)
	if err := os.MkdirAll(root, 0700); err != nil {
		return opt, err
	}

	np, proxyProvider, npResolvedMode, err := netproviders.Providers(nopt)
	if err != nil {
		return opt, err
	}

	exe, err := runhcsexecutor.New(runhcsexecutor.Opt{
		Root:   filepath.Join(root, "executor"),
		Binary: binary,
		DNS:    dns,
	}, np)
	if err != nil {
		return opt, err
	}

	var s ctdsnapshot.Snapshotter
	switch snapshotterName {
	case CIMSnapshotter:
		s, err = newCIMSnapshotter(filepath.Join(root, "snapshots"))
	default:
		s, err = windowssnapshot.NewWindowsSnapshotter(filepath.Join(root, "snapshots"))
	}
	if err != nil {
		return opt, err
	}

	localstore, err := local.NewStore(filepath.Join(root, "content"))
	if err != nil {
		return opt, err
	}

	db, err := boltutil.Open(filepath.Join(root, "containerdmeta.db"), 0644, &bolt.Options{
		FreelistType:   bolt.FreelistMapType,
		NoFreelistSync: true,
	}, policies...)
	if err != nil {
		return opt, err
	}

	mdb := ctdmetadata.NewDB(db, localstore, map[string]ctdsnapshot.Snapshotter{
		snapshotterName: timedSnapshotter{s},
	})
	if err := mdb.Init(context.TODO()); err != nil {
		return opt, err
	}

	c := containerdsnapshot.NewContentStore(mdb.ContentStore(), "buildkit")

	// Windows layers are written and compared through hcsshim, so one differ serves both roles.
	// (The CIM differ can't compare yet, so exporting layers from a CIM store isn't supported.)
	var diffs windowsdiff.CompareApplier
	if snapshotterName == CIMSnapshotter {
		diffs, err = windowsdiff.NewCimDiff(c)
	} else {
		diffs, err = windowsdiff.NewWindowsDiff(c)
	}
	if err != nil {
		return opt, err
	}

	id, err := base.ID(root)
	if err != nil {
		return opt, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	xlabels := map[string]string{
		wlabel.Executor:    "oci",
		wlabel.Snapshotter: snapshotterName,
		wlabel.Hostname:    hostname,
		wlabel.Network:     npResolvedMode,
	}
	maps.Copy(xlabels, labels)

	md, err := metadata.NewStore(filepath.Join(root, "metadata_v2.db"), policies...)
	if err != nil {
		return opt, err
	}

	opt = base.WorkerOpt{
		ID:               id,
		Root:             root,
		Labels:           xlabels,
		MetadataStore:    md,
		ContentMetadata:  db,
		NetworkProviders: np,
		ProxyProvider:    proxyProvider,
		Executor:         exe,
		Snapshotter:      containerdsnapshot.NewSnapshotter(snapshotterName, mdb.Snapshotter(snapshotterName), "buildkit", nil),
		ContentStore:     c,
		Applier:          diffs,
		Differ:           diffs,
		ImageStore:       nil, // explicitly
		Platforms:        []ocispecs.Platform{platforms.Normalize(platforms.DefaultSpec())},
		LeaseManager:     leaseutil.WithNamespace(ctdmetadata.NewLeaseManager(mdb), "buildkit"),
		GarbageCollect:   mdb.GarbageCollect,
		ParallelismSem:   parallelismSem,
		MountPoolRoot:    filepath.Join(root, "cachemounts"),
	}
	return opt, nil
}
