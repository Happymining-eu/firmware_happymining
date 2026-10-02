package applier

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
)

// ensureDir makes sure path is a real directory (not a symbolic link) owned
// by ownerUID, not writable by group or others, with exactly mode. A missing
// directory is created; its parent must exist. A directory that exists with
// another owner, or that is a link, is refused and left alone.
func ensureDir(path string, mode os.FileMode, ownerUID uint32) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("create %s: %w", path, err)
		}
		fi, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s is not a directory (a symbolic link is refused)", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != ownerUID {
		return fmt.Errorf("%s is not owned by uid %d", path, ownerUID)
	}
	if fi.Mode().Perm() != mode {
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("chmod %s: %w", path, err)
		}
	}
	return nil
}

// ensureGroupDir is ensureDir, then gives the directory to group gid. It is
// used only for the vectorizer's configuration directory, which its container
// user reads through that group; mode must not grant the group write access.
func ensureGroupDir(path string, mode os.FileMode, ownerUID uint32, gid int) error {
	if mode&0o022 != 0 {
		return fmt.Errorf("%s: a group-shared directory must not be writable by group or others", path)
	}
	if err := ensureDir(path, mode, ownerUID); err != nil {
		return err
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: no ownership information", path)
	}
	if int(st.Gid) != gid {
		// ensureDir has just checked that this is a real directory owned by
		// ownerUID; Lchown does not follow a link put there since.
		if err := os.Lchown(path, int(ownerUID), gid); err != nil {
			return fmt.Errorf("chown %s: %w", path, err)
		}
	}
	return nil
}

// writeGroupFile is writeFile with the file given to group gid.
func writeGroupFile(dir, name string, data []byte, mode os.FileMode, ownerUID uint32, gid int) error {
	if mode&0o022 != 0 {
		return fmt.Errorf("a group-shared file must not be writable by group or others")
	}
	if name == "" || strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
		return fmt.Errorf("invalid file name")
	}
	path := filepath.Join(dir, name)
	fi, err := os.Lstat(path)
	switch {
	case err == nil && !fi.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file (a symbolic link is refused)", path)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s: %w", path, err)
	}
	return fsx.WriteFileAtomic(path, data, mode, &fsx.Owner{UID: int(ownerUID), GID: gid})
}

// ensureDirs is ensureDir for a chain of directories, outermost first.
func ensureDirs(mode os.FileMode, ownerUID uint32, paths ...string) error {
	for _, p := range paths {
		if err := ensureDir(p, mode, ownerUID); err != nil {
			return err
		}
	}
	return nil
}

// checkExistingDir checks without creating or changing anything.
func checkExistingDir(path string, ownerUID uint32) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s is not a directory (a symbolic link is refused)", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != ownerUID {
		return fmt.Errorf("%s is not owned by uid %d", path, ownerUID)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others", path)
	}
	return nil
}

// writeFile writes data to dir/name atomically (temporary file in the same
// directory, fsync, rename, directory fsync) with mode. dir must have been
// checked with ensureDir. A symbolic link or anything but a regular file at
// the name is refused rather than replaced.
func writeFile(dir, name string, data []byte, mode os.FileMode) error {
	if name == "" || strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
		return fmt.Errorf("invalid file name")
	}
	path := filepath.Join(dir, name)
	fi, err := os.Lstat(path)
	switch {
	case err == nil && !fi.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file (a symbolic link is refused)", path)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s: %w", path, err)
	}
	return fsx.WriteFileAtomic(path, data, mode, nil)
}

// readFile reads a regular file of at most max bytes without following a
// symbolic link in its last component. When ownerUID is not nil the file must
// be owned by it and not writable by group or others. A missing file is an
// error that matches fs.ErrNotExist.
func readFile(path string, max int64, ownerUID *uint32) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("%s cannot be opened (a symbolic link is refused): %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if ownerUID != nil {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != *ownerUID {
			return nil, fmt.Errorf("%s is not owned by uid %d", path, *ownerUID)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return nil, fmt.Errorf("%s is writable by group or others", path)
		}
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return data, nil
}

// removeFile removes dir/name if it is there. A directory is not removed.
func removeFile(dir, name string) error {
	if name == "" || strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
		return fmt.Errorf("invalid file name")
	}
	path := filepath.Join(dir, name)
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// regularFileExists reports whether path is a regular file (not a link).
func regularFileExists(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode().IsRegular()
}

var errNotExist = fs.ErrNotExist

// lock is an advisory flock on a file in the state directory.
type lock struct{ f *os.File }

// ErrBusy is returned by tryLock when another process holds the lock.
var ErrBusy = errors.New("another HappyMining helper task holds the lock")

func openLock(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
}

// takeLock waits for an exclusive lock.
func takeLock(path string) (*lock, error) {
	f, err := openLock(path)
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", filepath.Base(path), err)
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock %s: %w", filepath.Base(path), err)
	}
	return &lock{f: f}, nil
}

// tryLock takes an exclusive lock or returns ErrBusy.
func tryLock(path string) (*lock, error) {
	f, err := openLock(path)
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", filepath.Base(path), err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if err == syscall.EWOULDBLOCK {
			return nil, ErrBusy
		}
		return nil, fmt.Errorf("lock %s: %w", filepath.Base(path), err)
	}
	return &lock{f: f}, nil
}

func (l *lock) release() {
	if l != nil && l.f != nil {
		_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
		_ = l.f.Close()
		l.f = nil
	}
}

// ensureStateDir creates or checks the root-only state directory and its
// fixed subdirectories.
func (e *Env) ensureStateDir() error {
	if err := ensureDir(e.Paths.StateDir, 0o700, e.OwnerUID); err != nil {
		return err
	}
	for _, sub := range []string{pluginsDir, nasCredDir, updatesDir, packagesDir} {
		if err := ensureDir(e.Paths.state(sub), 0o700, e.OwnerUID); err != nil {
			return err
		}
	}
	return nil
}
