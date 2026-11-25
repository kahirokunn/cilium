// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// This file was not reviewed by a human before submission

//go:build linux

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/testutils"
)

func writeTestFile(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, nil, 0o600))
}

func mountTmpfs(t *testing.T, dir string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, unix.Mount("tmpfs", dir, "tmpfs", 0, ""))
	t.Cleanup(func() { assert.NoError(t, unix.Unmount(dir, unix.MNT_DETACH)) })
}

func TestRemoveRuntimeAndLibraryDirs(t *testing.T) {
	root := t.TempDir()
	runtimeDir := filepath.Join(root, "run")
	libDir := filepath.Join(root, "lib")
	writeTestFile(t, filepath.Join(runtimeDir, "state", "file"))
	writeTestFile(t, filepath.Join(libDir, "bpf", "file"))

	require.NoError(t, removeRuntimeAndLibraryDirs(runtimeDir, libDir))

	assert.NoDirExists(t, runtimeDir)
	assert.NoDirExists(t, libDir)
}

func TestRemoveRuntimeAndLibraryDirsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	runtimeDir := filepath.Join(root, "run")
	libDir := filepath.Join(root, "lib")
	writeTestFile(t, filepath.Join(target, "file"))
	writeTestFile(t, filepath.Join(libDir, "file"))
	require.NoError(t, os.Symlink(target, runtimeDir))

	require.NoError(t, removeRuntimeAndLibraryDirs(runtimeDir, libDir))

	assert.NoFileExists(t, runtimeDir)
	assert.FileExists(t, filepath.Join(target, "file"))
	assert.NoDirExists(t, libDir)
}

func TestRemoveRuntimeAndLibraryDirsRefusesRoot(t *testing.T) {
	libDir := t.TempDir()

	assert.Error(t, removeRuntimeAndLibraryDirs("/", libDir))
	assert.DirExists(t, libDir)
}

func TestPrivilegedRemoveRuntimeAndLibraryDirsMountPoint(t *testing.T) {
	testutils.PrivilegedTest(t)

	for _, tt := range []struct {
		name           string
		readOnlyParent bool
	}{
		{name: "writable parent", readOnlyParent: false},
		{name: "read-only parent", readOnlyParent: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			parent := filepath.Join(root, "parent")
			runtimeDir := filepath.Join(parent, "run")
			libDir := filepath.Join(root, "lib")

			mountTmpfs(t, parent)
			mountTmpfs(t, runtimeDir)
			writeTestFile(t, filepath.Join(runtimeDir, "file"))
			writeTestFile(t, filepath.Join(runtimeDir, "state", "file"))
			writeTestFile(t, filepath.Join(libDir, "file"))
			if tt.readOnlyParent {
				require.NoError(t, unix.Mount("", parent, "", unix.MS_REMOUNT|unix.MS_RDONLY, ""))
			}

			require.NoError(t, removeRuntimeAndLibraryDirs(runtimeDir, libDir))

			entries, err := os.ReadDir(runtimeDir)
			require.NoError(t, err)
			assert.Empty(t, entries)
			assert.FileExists(t, filepath.Join(libDir, "file"))
		})
	}
}

func TestPrivilegedRemoveRuntimeAndLibraryDirsBusyChild(t *testing.T) {
	testutils.PrivilegedTest(t)

	root := t.TempDir()
	runtimeDir := filepath.Join(root, "run")
	libDir := filepath.Join(root, "lib")
	mountTmpfs(t, runtimeDir)
	mountTmpfs(t, filepath.Join(runtimeDir, "mounted"))
	writeTestFile(t, filepath.Join(runtimeDir, "state", "file"))
	writeTestFile(t, filepath.Join(libDir, "file"))

	assert.ErrorIs(t, removeRuntimeAndLibraryDirs(runtimeDir, libDir), unix.EBUSY)

	assert.NoDirExists(t, filepath.Join(runtimeDir, "state"))
	assert.FileExists(t, filepath.Join(libDir, "file"))
}

func TestPrivilegedRemoveIfExistsReadOnly(t *testing.T) {
	testutils.PrivilegedTest(t)

	dir := filepath.Join(t.TempDir(), "mount")
	mountTmpfs(t, dir)
	existing := filepath.Join(dir, "existing")
	writeTestFile(t, existing)
	require.NoError(t, unix.Mount("", dir, "", unix.MS_REMOUNT|unix.MS_RDONLY, ""))

	assert.NoError(t, removeIfExists(filepath.Join(dir, "missing")))
	assert.ErrorIs(t, removeIfExists(existing), unix.EROFS)
}
