//go:build windows

package main

import (
	"context"
	"maps"
	"strconv"

	"github.com/moby/buildkit/cmd/buildkitd/config"
	"github.com/moby/buildkit/util/bklog"
	"github.com/moby/buildkit/util/network/cniprovider"
	"github.com/moby/buildkit/util/network/netproviders"
	"github.com/moby/buildkit/worker"
	"github.com/moby/buildkit/worker/base"
	"github.com/moby/buildkit/worker/hcs"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v3"
	"golang.org/x/sync/semaphore"
)

func init() {
	defaultConf, _ := defaultConf()

	enabledValue := func(b *bool) string {
		if b == nil {
			return "auto"
		}
		return strconv.FormatBool(*b)
	}

	flags := []cli.Flag{
		&cli.StringFlag{
			Name:  "oci-worker",
			Usage: "enable the daemon-less oci worker, which runs Windows containers through runhcs (true/false/auto; auto is off on Windows)",
			Value: enabledValue(defaultConf.Workers.OCI.Enabled),
		},
		&cli.StringSliceFlag{
			Name:  "oci-worker-labels",
			Usage: "user-specific annotation labels (com.example.foo=bar)",
		},
		&cli.StringSliceFlag{
			Name:  "oci-worker-platform",
			Usage: "override supported platforms for worker",
		},
		&cli.StringFlag{
			Name:  "oci-worker-net",
			Usage: "worker network type (auto, cni or none)",
			Value: defaultConf.Workers.OCI.Mode,
		},
		&cli.StringFlag{
			Name:  "oci-cni-config-path",
			Usage: "path of cni config file",
			Value: defaultConf.Workers.OCI.CNIConfigPath,
		},
		&cli.StringFlag{
			Name:  "oci-cni-binary-dir",
			Usage: "path of cni binary files",
			Value: defaultConf.Workers.OCI.CNIBinaryPath,
		},
		&cli.StringFlag{
			Name:  "oci-worker-binary",
			Usage: "path of the runhcs binary used to run build steps",
			Value: defaultConf.Workers.OCI.Binary,
		},
		&cli.BoolFlag{
			Name:  "oci-worker-gc",
			Usage: "enable cache garbage collection for the oci worker (default true; the default policy keeps 20% of the disk free)",
			Value: true,
		},
		&cli.StringFlag{
			Name:  "oci-worker-snapshotter",
			Usage: "snapshotter for the oci worker: windows (default) or cim (layers stored as CimFS images)",
			Value: "windows",
		},
		&cli.IntFlag{
			Name:  "oci-max-parallelism",
			Usage: "maximum number of parallel build steps that can be run at the same time (0 is unlimited)",
		},
	}

	registerWorkerInitializer(
		workerInitializer{
			fn:       ociWorkerInitializer,
			priority: 0,
		},
		flags...,
	)
}

func applyOCIFlags(c *cli.Command, cfg *config.Config) error {
	if c.IsSet("oci-worker") {
		boolOrAuto, err := parseBoolOrAuto(c.String("oci-worker"))
		if err != nil {
			return err
		}
		cfg.Workers.OCI.Enabled = boolOrAuto
	}

	labels, err := attrMap(c.StringSlice("oci-worker-labels"))
	if err != nil {
		return err
	}
	if cfg.Workers.OCI.Labels == nil {
		cfg.Workers.OCI.Labels = make(map[string]string)
	}
	maps.Copy(cfg.Workers.OCI.Labels, labels)

	if platforms := c.StringSlice("oci-worker-platform"); len(platforms) != 0 {
		cfg.Workers.OCI.Platforms = platforms
	}
	if c.IsSet("oci-worker-net") {
		cfg.Workers.OCI.Mode = c.String("oci-worker-net")
	}
	if c.IsSet("oci-cni-config-path") {
		cfg.Workers.OCI.CNIConfigPath = c.String("oci-cni-config-path")
	}
	if c.IsSet("oci-cni-binary-dir") {
		cfg.Workers.OCI.CNIBinaryPath = c.String("oci-cni-binary-dir")
	}
	if c.IsSet("oci-worker-binary") {
		cfg.Workers.OCI.Binary = c.String("oci-worker-binary")
	}
	if c.IsSet("oci-worker-gc") {
		v := c.Bool("oci-worker-gc")
		cfg.Workers.OCI.GC = &v
	}
	if c.IsSet("oci-worker-snapshotter") {
		cfg.Workers.OCI.Snapshotter = c.String("oci-worker-snapshotter")
	}
	if c.IsSet("oci-max-parallelism") {
		cfg.Workers.OCI.MaxParallelism = c.Int("oci-max-parallelism")
	}
	return nil
}

func ociWorkerInitializer(c *cli.Command, common workerInitializerOpt) ([]worker.Worker, error) {
	if err := applyOCIFlags(c, common.config); err != nil {
		return nil, err
	}

	cfg := common.config.Workers.OCI

	// Unlike Linux, "auto" does not enable this worker: the containerd worker is the default on
	// Windows and only one default worker can be used.
	if cfg.Enabled == nil || !*cfg.Enabled {
		return nil, nil
	}

	hosts := resolverFunc(common.config)
	dns := getDNSConfig(common.config.DNS)

	nc := netproviders.Opt{
		Mode: cfg.Mode,
		CNI: cniprovider.Opt{
			Root:       common.config.Root,
			ConfigPath: cfg.CNIConfigPath,
			BinaryDir:  cfg.CNIBinaryPath,
			PoolSize:   cfg.CNIPoolSize,
		},
	}

	var parallelismSem *semaphore.Weighted
	if cfg.MaxParallelism > 0 {
		parallelismSem = semaphore.NewWeighted(int64(cfg.MaxParallelism))
	}

	opt, err := hcs.NewWorkerOpt(common.config.Root, cfg.Labels, nc, dns, cfg.Binary, cfg.Snapshotter, parallelismSem, common.compaction...)
	if err != nil {
		return nil, err
	}
	opt.GCPolicy = getGCPolicy(cfg.GCConfig, common.config.Root)
	opt.BuildkitVersion = getBuildkitVersion()
	opt.RegistryHosts = hosts

	if platformsStr := cfg.Platforms; len(platformsStr) != 0 {
		platforms, err := parsePlatforms(platformsStr)
		if err != nil {
			return nil, errors.Wrap(err, "invalid platforms")
		}
		opt.Platforms = platforms
	}
	bklog.L.Debug("starting the daemon-less Windows oci worker")
	w, err := base.NewWorker(context.TODO(), opt)
	if err != nil {
		return nil, err
	}
	return []worker.Worker{w}, nil
}
