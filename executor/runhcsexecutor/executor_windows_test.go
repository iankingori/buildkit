//go:build windows

package runhcsexecutor

import (
	"encoding/json"
	"os/exec"
	"testing"

	"github.com/containerd/containerd/v2/core/mount"
	gatewayapi "github.com/moby/buildkit/frontend/gateway/pb"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestLayerFolders(t *testing.T) {
	m := mount.Mount{
		Type:    "windows-layer",
		Source:  `C:\snap\3`,
		Options: []string{"rw", `parentLayerPaths=["C:\\snap\\2","C:\\snap\\1"]`},
	}
	got, err := layerFolders([]mount.Mount{m})
	require.NoError(t, err)
	// parents keep the snapshotter's order and the scratch layer comes last
	require.Equal(t, []string{`C:\snap\2`, `C:\snap\1`, `C:\snap\3`}, got)

	_, err = layerFolders(nil)
	require.Error(t, err)
	_, err = layerFolders([]mount.Mount{m, m})
	require.Error(t, err)
	_, err = layerFolders([]mount.Mount{{Type: "bind", Source: `C:\x`}})
	require.Error(t, err)
	_, err = layerFolders([]mount.Mount{{Type: "windows-layer", Source: `C:\x`, Options: []string{"parentLayerPaths=notjson"}}})
	require.Error(t, err)

	base, err := layerFolders([]mount.Mount{{Type: "windows-layer", Source: `C:\snap\1`}})
	require.NoError(t, err)
	require.Equal(t, []string{`C:\snap\1`}, base)
}

func TestRootfsFromMounts(t *testing.T) {
	cim := mount.Mount{
		Type:    mount.CimFSMountType,
		Source:  `C:\snap\3`,
		Options: []string{"rw", `cimpath=C:\cims\3.cim`, `parentLayerPaths=["C:\\snap\\2"]`, `parentCimPaths=["C:\\cims\\2.cim"]`},
	}
	got, err := rootfsFromMounts([]mount.Mount{cim})
	require.NoError(t, err)
	require.Equal(t, `C:\snap\3`, got.scratch)
	require.Empty(t, got.folders)
	// runhcs reads containerd's mount JSON (lower-case keys)
	var m struct {
		Type    string   `json:"type"`
		Source  string   `json:"source"`
		Options []string `json:"options"`
	}
	require.NoError(t, json.Unmarshal(got.cimMount, &m))
	require.Equal(t, "CimFS", m.Type)
	require.Equal(t, cim.Source, m.Source)
	require.Equal(t, cim.Options, m.Options)

	wl := mount.Mount{Type: "windows-layer", Source: `C:\snap\3`, Options: []string{"rw", `parentLayerPaths=["C:\\snap\\2"]`}}
	got, err = rootfsFromMounts([]mount.Mount{wl})
	require.NoError(t, err)
	require.Nil(t, got.cimMount)
	require.Equal(t, `C:\snap\3`, got.scratch)
	require.Equal(t, []string{`C:\snap\2`, `C:\snap\3`}, got.folders)
}

func TestSetCommandLine(t *testing.T) {
	p := &specs.Process{Args: []string{"old"}}
	setCommandLine(p, []string{"cmd", "/S", "/C", `cmd /c "echo hi"`})
	require.Nil(t, p.Args)
	require.Equal(t, `cmd /S /C cmd /c "echo hi"`, p.CommandLine)
}

func TestExitError(t *testing.T) {
	require.NoError(t, exitError(nil, nil))
	require.NoError(t, exitError(nil, []int{0, 2}))

	// a real non-zero exit from a child process
	err := exec.Command("cmd", "/c", "exit 3").Run()
	var ee *exec.ExitError
	require.True(t, errors.As(err, &ee))

	got := exitError(err, nil)
	var ge *gatewayapi.ExitError
	require.True(t, errors.As(got, &ge))
	require.Equal(t, uint32(3), ge.ExitCode)

	require.NoError(t, exitError(err, []int{3}), "listed exit codes are accepted")
	require.Error(t, exitError(err, []int{1, 2}))

	// failing to run at all is an unknown exit status, not success
	got = exitError(errors.New("boom"), nil)
	require.True(t, errors.As(got, &ge))
	require.Equal(t, uint32(gatewayapi.UnknownExitStatus), ge.ExitCode)
}
