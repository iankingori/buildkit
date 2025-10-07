//go:build windows

package main

import (
	"github.com/moby/buildkit/cmd/buildkitd/config"
	"github.com/moby/buildkit/worker"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

// Windows-specific OCI worker implementation (stub for now)
func initializePlatformOCIWorker(c *cli.Context, common workerInitializerOpt, cfg config.OCIConfig) ([]worker.Worker, error) {
	// TODO: Implement Windows OCI worker using runhcs
	return nil, errors.New("OCI worker not yet supported on Windows")
}

// Windows-specific OCI binary validation (stub for now)
func validOCIBinary() bool {
	// TODO: Check for runhcs binary
	return false
}

// Windows-specific user namespace detection (always false on Windows)
func isRunningInUserNS() bool {
	return false
}

// Windows-specific rootless mode validation (not supported on Windows)
func validateRootlessMode() error {
	return errors.New("rootless mode is not supported on Windows")
}
