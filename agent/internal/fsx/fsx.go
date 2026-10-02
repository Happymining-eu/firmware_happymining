// Package fsx contains the small file-system helpers shared by the agent:
// atomic writes (temp file + fsync + rename + directory fsync) and ownership
// handling for files created by root on behalf of the unprivileged agent.
package fsx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Owner is a numeric file owner.
type Owner struct {
	UID int
	GID int
}

// tmpMarker is part of every temporary file name created by WriteFileAtomic.
const tmpMarker = ".tmp-"

// IsTempName reports whether name looks like a leftover temporary file of
// WriteFileAtomic (for example after a crash between write and rename).
func IsTempName(name string) bool {
	return strings.HasPrefix(name, ".") && strings.Contains(name, tmpMarker)
}

// WriteFileAtomic writes data to path so that readers see either the old or
// the new content, never a partial file: it writes a temporary file in the same
// directory, fsyncs it, renames it over path and fsyncs the directory.
// If owner is not nil the file is chowned before the rename.
func WriteFileAtomic(path string, data []byte, perm os.FileMode, owner *Owner) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+tmpMarker+"*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmp := f.Name()
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if _, err := f.Write(data); err != nil {
		return fail(fmt.Errorf("write temporary file: %w", err))
	}
	if err := f.Chmod(perm); err != nil {
		return fail(fmt.Errorf("chmod temporary file: %w", err))
	}
	if owner != nil {
		if err := f.Chown(owner.UID, owner.GID); err != nil {
			return fail(fmt.Errorf("chown temporary file: %w", err))
		}
	}
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("fsync temporary file: %w", err))
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename into place: %w", err)
	}
	return SyncDir(dir)
}

// SyncDir fsyncs a directory so that a rename or unlink inside it is durable.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open directory for fsync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync directory: %w", err)
	}
	return nil
}

// OwnerOf returns the numeric owner of path.
func OwnerOf(path string) (*Owner, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("cannot determine owner of %s", path)
	}
	return &Owner{UID: int(st.Uid), GID: int(st.Gid)}, nil
}

// OwnerForNewFiles returns the owner that files created inside dir should get
// when the current process is root (so that `sudo happyminingctl pair` leaves a
// credential the unprivileged agent can read). For non-root callers it returns
// nil: the files simply belong to the caller.
func OwnerForNewFiles(dir string) (*Owner, error) {
	if os.Geteuid() != 0 {
		return nil, nil
	}
	return OwnerOf(dir)
}
