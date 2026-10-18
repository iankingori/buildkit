//go:build windows

// Package runhcsexecutor runs build steps in Windows containers by driving the runhcs binary,
// the same way runcexecutor drives runc on Linux.
package runhcsexecutor

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd/v2/core/mount"
	containerdoci "github.com/containerd/containerd/v2/pkg/oci"
	"github.com/moby/buildkit/executor"
	"github.com/moby/buildkit/executor/oci"
	resourcestypes "github.com/moby/buildkit/executor/resources/types"
	gatewayapi "github.com/moby/buildkit/frontend/gateway/pb"
	"github.com/moby/buildkit/identity"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/util/bklog"
	"github.com/moby/buildkit/util/network"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Opt configures the executor.
type Opt struct {
	// Root is the directory for executor state (bundles, logs).
	Root string
	// Binary is the runhcs binary to use. If empty, "runhcs" is looked up in PATH.
	Binary string
	DNS    *oci.DNSConfig
}

type runhcsExecutor struct {
	binary           string
	root             string
	networkProviders map[pb.NetMode]network.Provider
}

// New returns an executor backed by runhcs.
func New(opt Opt, networkProviders map[pb.NetMode]network.Provider) (executor.Executor, error) {
	binary := opt.Binary
	if binary == "" {
		binary = "runhcs"
	}
	path, err := exec.LookPath(binary)
	if err != nil {
		return nil, errors.Wrapf(err, "runhcs binary %q not found; set --oci-worker-binary", binary)
	}
	if err := os.MkdirAll(opt.Root, 0o700); err != nil {
		return nil, err
	}
	return &runhcsExecutor{binary: path, root: opt.Root, networkProviders: networkProviders}, nil
}

// rootfsMountAnnotation tells runhcs where the JSON description of a CIM root file system is; it is
// the annotation runhcs reads (hcsshim feature/runhcs-cim).
const rootfsMountAnnotation = "io.runhcs.rootfs-mount"

// rootfs says how runhcs gets the container's root file system.
type rootfs struct {
	// scratch is the writable layer directory.
	scratch string
	// folders are the layer folders (parents..., scratch) of a windows-layer rootfs.
	folders []string
	// cimMount describes a forked CIM chain plus scratch (containerd mount JSON), empty for windows-layer.
	cimMount []byte
}

// rootfsFromMounts understands the mounts of both Windows snapshotters.
func rootfsFromMounts(mounts []mount.Mount) (*rootfs, error) {
	if len(mounts) == 1 && mounts[0].Type == mount.CimFSMountType {
		m := mounts[0]
		js, err := json.Marshal(struct {
			Type    string   `json:"type"`
			Source  string   `json:"source"`
			Options []string `json:"options"`
		}{m.Type, m.Source, m.Options})
		if err != nil {
			return nil, err
		}
		return &rootfs{scratch: m.Source, cimMount: js}, nil
	}
	folders, err := layerFolders(mounts)
	if err != nil {
		return nil, err
	}
	return &rootfs{scratch: folders[len(folders)-1], folders: folders}, nil
}

// layerFolders converts the Windows snapshotter mounts into the layer folder list that runhcs
// expects: the parent layers (as given by the snapshotter) followed by the writable scratch layer.
func layerFolders(mounts []mount.Mount) ([]string, error) {
	if len(mounts) != 1 {
		return nil, errors.Errorf("expected exactly one windows-layer mount, got %d", len(mounts))
	}
	m := mounts[0]
	if m.Type != "windows-layer" {
		return nil, errors.Errorf("unsupported rootfs mount type %q", m.Type)
	}
	var parents []string
	for _, o := range m.Options {
		if v, ok := strings.CutPrefix(o, "parentLayerPaths="); ok {
			if err := json.Unmarshal([]byte(v), &parents); err != nil {
				return nil, errors.Wrap(err, "invalid parentLayerPaths option")
			}
		}
	}
	return append(parents, m.Source), nil
}

func (w *runhcsExecutor) Run(ctx context.Context, id string, root executor.Mount, mounts []executor.Mount, process executor.ProcessInfo, started chan<- struct{}) (resourcestypes.Recorder, error) {
	meta := process.Meta
	if id == "" {
		// ExecOp doesn't name its containers; same approach as runcexecutor.
		id = identity.NewID()
	}
	if meta.Tty {
		return nil, errors.New("runhcs executor: tty is not supported yet")
	}
	if meta.Proxy != nil {
		return nil, errors.New("runhcs executor: proxy network mode is not supported yet")
	}
	provider, ok := w.networkProviders[meta.NetMode]
	if !ok {
		return nil, errors.Errorf("unknown network mode %s", meta.NetMode)
	}
	startedOnce := sync.OnceFunc(func() {
		if started != nil {
			close(started)
		}
	})
	defer startedOnce()

	mountable, err := root.Src.Mount(ctx, false)
	if err != nil {
		return nil, err
	}
	rootMounts, releaseRoot, err := mountable.Mount()
	if err != nil {
		return nil, err
	}
	defer releaseRoot()

	rfs, err := rootfsFromMounts(rootMounts)
	if err != nil {
		return nil, err
	}
	// Runs after the container is gone (defers are LIFO): the snapshotter can only commit the
	// scratch layer once HCS has fully released it.
	defer waitLayerReleased(ctx, rfs.scratch)

	namespace, err := provider.New(ctx, meta.Hostname, network.NamespaceOptions{})
	if err != nil {
		return nil, err
	}
	defer namespace.Close()

	spec, cleanupSpec, err := oci.GenerateSpec(ctx, meta, mounts, id, "", "", namespace, "", oci.ProcessSandbox, nil, "", false, "", nil, containerdoci.WithUser(meta.User))
	if err != nil {
		return nil, err
	}
	defer cleanupSpec()
	if spec.Windows == nil {
		spec.Windows = &specs.Windows{}
	}
	// With no root path, hcsshim mounts the layers itself from the layer folders.
	spec.Root = &specs.Root{}
	// Pass the command line verbatim: an args array would make hcsshim escape embedded quotes in
	// a way cmd.exe rejects (same approach as the containerd executor on Windows).
	setCommandLine(spec.Process, meta.Args)
	spec.Windows.LayerFolders = rfs.folders

	bundle := filepath.Join(w.root, id)
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(bundle)
	if rfs.cimMount != nil {
		mountFile := filepath.Join(bundle, "rootfs-mount.json")
		if err := os.WriteFile(mountFile, rfs.cimMount, 0o600); err != nil {
			return nil, err
		}
		if spec.Annotations == nil {
			spec.Annotations = map[string]string{}
		}
		spec.Annotations[rootfsMountAnnotation] = mountFile
	}
	cfg, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	bklog.G(ctx).Debugf("runhcs spec for %s: %s", id, cfg)
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), cfg, 0o600); err != nil {
		return nil, err
	}

	pidFile := filepath.Join(bundle, "pid")
	args := []string{}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		// Keep runhcs' own log: it ignores errors while releasing layers after exit, so the log is
		// the only place they show up.
		args = append(args, "--debug", "--log", filepath.Join(w.root, id+".runhcs.log"))
	}
	args = append(args, "run",
		"--shim-log", filepath.Join(w.root, id+".shim.log"),
		"--pid-file", pidFile,
		"-b", bundle, id)
	cmd := exec.Command(w.binary, args...)
	cmd.Stdin = process.Stdin
	cmd.Stdout = process.Stdout
	cmd.Stderr = process.Stderr
	// The shim keeps the container's stdio handles for its whole life, so run only returns once
	// the container is done; forget also removes any state left behind by an abnormal exit.
	defer w.forget(id)

	if err := cmd.Start(); err != nil {
		return nil, errors.Wrap(err, "failed to start runhcs")
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			startedOnce()
			return nil, exitError(err, meta.ValidExitCodes)
		case <-ticker.C:
			if _, err := os.Stat(pidFile); err == nil {
				startedOnce()
				ticker.Stop()
			}
		case <-ctx.Done():
			// Terminate the container; runhcs run then returns on its own.
			w.forceDelete(id)
			err := <-done
			startedOnce()
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, errors.Wrap(ctxErr, "build step cancelled")
			}
			return nil, exitError(err, meta.ValidExitCodes)
		}
	}
}

func (w *runhcsExecutor) Exec(ctx context.Context, id string, process executor.ProcessInfo) error {
	meta := process.Meta
	if meta.Tty {
		return errors.New("runhcs executor: tty is not supported yet")
	}
	spec := specs.Process{
		Env: meta.Env,
		Cwd: meta.Cwd,
	}
	setCommandLine(&spec, meta.Args)
	if spec.Cwd == "" {
		spec.Cwd = `C:\`
	}
	dir, err := os.MkdirTemp(w.root, "exec-"+id+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	pj, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	pfile := filepath.Join(dir, "process.json")
	if err := os.WriteFile(pfile, pj, 0o600); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, w.binary, "exec", "-p", pfile, id)
	cmd.Stdin = process.Stdin
	cmd.Stdout = process.Stdout
	cmd.Stderr = process.Stderr
	return exitError(cmd.Run(), meta.ValidExitCodes)
}

// waitLayerReleased blocks until the scratch layer's sandbox.vhdx can be opened exclusively.
// runhcs unmounts the layers when the container exits but ignores errors, and detaching the
// disk can lag behind the exit, which makes the following snapshot commit fail with
// ERROR_SHARING_VIOLATION.
func waitLayerReleased(ctx context.Context, scratch string) {
	p, err := windows.UTF16PtrFromString(filepath.Join(scratch, "sandbox.vhdx"))
	if err != nil {
		return
	}
	start := time.Now()
	for {
		h, err := windows.CreateFile(p, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err == nil {
			windows.CloseHandle(h)
			bklog.G(ctx).Debugf("scratch layer %s released after %s", scratch, time.Since(start))
			return
		}
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return
		}
		if time.Since(start) > 30*time.Second {
			bklog.G(ctx).Warnf("scratch layer %s still in use after %s: %v", scratch, time.Since(start), err)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func setCommandLine(p *specs.Process, args []string) {
	p.Args = nil
	p.CommandLine = strings.Join(args, " ")
}

// forceDelete terminates the container and removes its runhcs state.
func (w *runhcsExecutor) forceDelete(id string) {
	out, err := exec.Command(w.binary, "delete", "-f", id).CombinedOutput()
	if err != nil {
		bklog.L.Debugf("runhcs delete -f %s: %v: %s", id, err, strings.TrimSpace(string(out)))
	}
}

// forget removes runhcs' registry state for the container. runhcs leaves it behind when the
// compute system disappears on its own, and `delete -f` then fails to clear it.
func (w *runhcsExecutor) forget(id string) {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, `Software\Microsoft\runhcs\default\`+id)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		bklog.L.Debugf("removing runhcs state for %s: %v", id, err)
	}
}

// exitError maps the result of a runhcs invocation to BuildKit's error type.
func exitError(err error, validExitCodes []int) error {
	exitErr := &gatewayapi.ExitError{ExitCode: uint32(gatewayapi.UnknownExitStatus), Err: err}
	if err == nil {
		exitErr.ExitCode = 0
	} else {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitErr = &gatewayapi.ExitError{ExitCode: uint32(ee.ExitCode())}
		}
	}
	if validExitCodes == nil {
		if exitErr.ExitCode == 0 {
			return nil
		}
	} else if slices.Contains(validExitCodes, int(exitErr.ExitCode)) {
		return nil
	}
	return exitErr
}
