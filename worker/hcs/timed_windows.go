//go:build windows

package hcs

import (
	"context"
	"time"

	ctdsnapshot "github.com/containerd/containerd/v2/core/snapshots"
	"github.com/moby/buildkit/util/bklog"
)

// timedSnapshotter logs how long the expensive snapshot operations take. Committing a layer on
// Windows re-imports the whole scratch layer, so its cost scales with the layer size.
type timedSnapshotter struct {
	ctdsnapshot.Snapshotter
}

func (s timedSnapshotter) Commit(ctx context.Context, name, key string, opts ...ctdsnapshot.Opt) error {
	start := time.Now()
	err := s.Snapshotter.Commit(ctx, name, key, opts...)
	d := time.Since(start)
	if usage, uerr := s.Snapshotter.Usage(ctx, name); err == nil && uerr == nil {
		bklog.G(ctx).Infof("snapshot commit %s took %s (%d bytes, %d inodes)", name, d.Round(time.Millisecond), usage.Size, usage.Inodes)
	} else {
		bklog.G(ctx).Infof("snapshot commit %s took %s (err=%v)", name, d.Round(time.Millisecond), err)
	}
	return err
}
