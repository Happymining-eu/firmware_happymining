package backup

import (
	"context"
	"errors"
	"io"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Linux constants that package syscall does not export.
const (
	// oPath is O_PATH: open a name without opening the file behind it. With
	// O_NOFOLLOW it opens a symbolic link itself. The value is the same on
	// every Linux architecture the agent is built for (amd64, arm64).
	oPath = 0x200000
	// atSymlinkNoFollow is AT_SYMLINK_NOFOLLOW.
	atSymlinkNoFollow = 0x100
	// utimeOmit is UTIME_OMIT: leave that timestamp alone.
	utimeOmit = (1 << 30) - 2
)

// Flags of every open in this package: never follow a symbolic link in the
// last component, never keep the descriptor across exec.
const openSafe = syscall.O_NOFOLLOW | syscall.O_CLOEXEC

// ignoringEINTR repeats fn while it is interrupted by a signal (the Go runtime
// sends signals to its own threads, and a slow file system such as NFS lets
// them interrupt an open).
func ignoringEINTR(fn func() error) error {
	for {
		err := fn()
		if err != syscall.EINTR {
			return err
		}
	}
}

// relName refuses, at the system-call boundary, any name that is not one
// component relative to the directory descriptor: an absolute name makes the
// kernel ignore dirfd altogether, and a name with a slash or ".." leaves the
// directory. Callers validate names before they get here; this is the second
// check, so that a mistake or a removed check upstream cannot turn
// unlinkat(dirfd, "/etc/passwd") into the deletion of a system file by a
// process that runs as root. "." (the directory itself) is allowed.
func relName(name string) error {
	if name == "" || name == ".." || strings.ContainsAny(name, "/\x00") {
		return ErrUnsafePath
	}
	return nil
}

// openat opens name relative to the directory dirfd.
func openat(dirfd int, name string, flags int, mode uint32) (int, error) {
	if err := relName(name); err != nil {
		return -1, err
	}
	var fd int
	err := ignoringEINTR(func() error {
		var e error
		fd, e = syscall.Openat(dirfd, name, flags, mode)
		return e
	})
	if err != nil {
		return -1, err
	}
	return fd, nil
}

// openDir opens the directory at path (symbolic links in path are followed:
// path comes from the caller, not from an archive).
func openDir(path string) (int, error) {
	var fd int
	err := ignoringEINTR(func() error {
		var e error
		fd, e = syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		return e
	})
	if err != nil {
		return -1, err
	}
	return fd, nil
}

func fstat(fd int) (syscall.Stat_t, error) {
	var st syscall.Stat_t
	err := ignoringEINTR(func() error { return syscall.Fstat(fd, &st) })
	return st, err
}

func mkdirat(dirfd int, name string, mode uint32) error {
	if err := relName(name); err != nil {
		return err
	}
	return ignoringEINTR(func() error { return syscall.Mkdirat(dirfd, name, mode) })
}

// unlinkat removes the name itself (a symbolic link is removed, not followed).
func unlinkat(dirfd int, name string) error {
	if err := relName(name); err != nil {
		return err
	}
	return ignoringEINTR(func() error { return syscall.Unlinkat(dirfd, name) })
}

// renameat renames from to to, both relative to dirfd.
func renameat(dirfd int, from, to string) error {
	if err := relName(from); err != nil {
		return err
	}
	if err := relName(to); err != nil {
		return err
	}
	return ignoringEINTR(func() error { return syscall.Renameat(dirfd, from, dirfd, to) })
}

// symlinkat creates the symbolic link name, relative to dirfd, pointing to
// target. It fails with EEXIST if name exists.
func symlinkat(target string, dirfd int, name string) error {
	if err := relName(name); err != nil {
		return err
	}
	t, err := syscall.BytePtrFromString(target)
	if err != nil {
		return err
	}
	n, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	return ignoringEINTR(func() error {
		_, _, e := syscall.Syscall(syscall.SYS_SYMLINKAT, uintptr(unsafe.Pointer(t)), uintptr(dirfd), uintptr(unsafe.Pointer(n)))
		if e != 0 {
			return e
		}
		return nil
	})
}

// readlinkFd returns the target of the symbolic link that fd refers to (fd was
// opened with O_PATH|O_NOFOLLOW).
func readlinkFd(fd int) (string, error) {
	empty, err := syscall.BytePtrFromString("")
	if err != nil {
		return "", err
	}
	for size := 256; ; size *= 2 {
		buf := make([]byte, size)
		var n uintptr
		err := ignoringEINTR(func() error {
			var e syscall.Errno
			n, _, e = syscall.Syscall6(syscall.SYS_READLINKAT, uintptr(fd), uintptr(unsafe.Pointer(empty)),
				uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
			if e != 0 {
				return e
			}
			return nil
		})
		if err != nil {
			return "", err
		}
		if int(n) < size {
			return string(buf[:n]), nil
		}
		if size > maxPathLen {
			return "", syscall.ENAMETOOLONG
		}
	}
}

// futimens sets the modification time of the file fd refers to and leaves its
// access time alone.
func futimens(fd int, mtime time.Time) error {
	ts := [2]syscall.Timespec{
		{Sec: 0, Nsec: utimeOmit},
		syscall.NsecToTimespec(mtime.UnixNano()),
	}
	return ignoringEINTR(func() error {
		_, _, e := syscall.Syscall6(syscall.SYS_UTIMENSAT, uintptr(fd), 0, uintptr(unsafe.Pointer(&ts[0])), 0, 0, 0)
		if e != 0 {
			return e
		}
		return nil
	})
}

func closeFd(fd int) {
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
}

// ctxReader fails with the context's error once the context is done, so that a
// long copy stops promptly.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// isSymlinkErr reports whether an open with O_NOFOLLOW (and possibly
// O_DIRECTORY) failed because the name is not what it must be: a symbolic
// link (ELOOP) or not a directory (ENOTDIR).
func isSymlinkErr(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR)
}
