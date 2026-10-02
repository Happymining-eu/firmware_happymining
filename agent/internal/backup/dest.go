package backup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Entry is one archive at a destination.
type Entry struct {
	// Name is the archive name (it parses with ParseArchiveName).
	Name string
	// Size is the size of the archive in bytes.
	Size int64
	// ModTime is when the destination last stored it; informative only.
	ModTime time.Time
}

// Destination is where archives are kept. Every method takes archive names
// only (ErrInvalidName otherwise): a destination cannot be made to read, write
// or delete anything else.
type Destination interface {
	// Put stores everything read from r as name, replacing an archive of the
	// same name. If r fails, or the context ends, nothing is stored under
	// name: a failed Put leaves no archive that looks complete.
	Put(ctx context.Context, name string, r io.Reader) error
	// Get opens the archive name. A missing archive is ErrNotFound.
	Get(ctx context.Context, name string) (io.ReadCloser, error)
	// List returns the archives at the destination, sorted by name. Whatever
	// else is there is left out.
	List(ctx context.Context) ([]Entry, error)
	// Delete removes the archive name. Deleting an archive that is not there
	// is not an error.
	Delete(ctx context.Context, name string) error
}

// maxListEntries bounds the archives one List returns.
const maxListEntries = 100_000

// checkArchiveName is the gate of every Destination method.
func checkArchiveName(name string) error {
	if _, _, err := ParseArchiveName(name); err != nil {
		return err
	}
	return nil
}

// DirDestination keeps archives in one directory, typically a directory of a
// NAS share mounted read-write under /srv/happymining/nas/<id>.
//
// The directory is opened once and every operation is made relative to that
// open directory, by name, without following symbolic links: a link planted in
// the directory (a NAS is written by other people) is never read through,
// written through or listed. An upload goes to a temporary name and is renamed
// into place once it is complete and flushed.
type DirDestination struct {
	dirfd int
	path  string
}

// OpenDirDestination opens the directory subpath inside root for archives.
//
// root is the mount point of the share, an absolute path chosen by the
// caller; it is trusted. subpath is the relative path inside the share from
// the configuration ("" for the root of the share; no empty, "." or ".."
// segment). Each of its components is opened without following symbolic
// links, so that a link on the share cannot lead the backup elsewhere, and is
// created (mode 0700) if it does not exist.
//
// The caller must have checked that the share is mounted at root: this
// function cannot tell a mounted share from the empty directory under it.
func OpenDirDestination(root, subpath string) (*DirDestination, error) {
	if !filepath.IsAbs(root) || strings.ContainsRune(root, 0) {
		return nil, fmt.Errorf("%w: the directory must be an absolute path", ErrInvalidConfig)
	}
	var comps []string
	if subpath != "" {
		if len(subpath) > 512 {
			return nil, fmt.Errorf("%w: subpath too long", ErrInvalidConfig)
		}
		comps = strings.Split(subpath, "/")
		for _, c := range comps {
			if c == "" || c == "." || c == ".." || len(c) > maxNameLen || strings.ContainsRune(c, 0) {
				return nil, fmt.Errorf("%w: subpath has an empty, \".\" or \"..\" segment", ErrInvalidConfig)
			}
		}
	}
	fd, err := openDir(root)
	if err != nil {
		return nil, fmt.Errorf("backup: open destination directory: %w", err)
	}
	for _, c := range comps {
		if err := mkdirat(fd, c, 0o700); err != nil && !errors.Is(err, syscall.EEXIST) {
			closeFd(fd)
			return nil, fmt.Errorf("backup: create destination directory: %w", err)
		}
		next, err := openat(fd, c, syscall.O_RDONLY|syscall.O_DIRECTORY|openSafe, 0)
		closeFd(fd)
		if err != nil {
			if isSymlinkErr(err) {
				return nil, fmt.Errorf("%w: a component of the destination subpath is a symbolic link or not a directory", ErrUnsafePath)
			}
			return nil, fmt.Errorf("backup: open destination directory: %w", err)
		}
		fd = next
	}
	return &DirDestination{dirfd: fd, path: filepath.Join(root, filepath.FromSlash(subpath))}, nil
}

// Path returns the directory's path, for messages.
func (d *DirDestination) Path() string { return d.path }

// Close releases the directory. The destination must not be used afterwards.
func (d *DirDestination) Close() error {
	fd := d.dirfd
	d.dirfd = -1
	if fd < 0 {
		return nil
	}
	return syscall.Close(fd)
}

// Put implements Destination.
func (d *DirDestination) Put(ctx context.Context, name string, r io.Reader) error {
	if err := checkArchiveName(name); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("backup: store archive: %w", err)
	}
	tmp := "." + name + ".tmp-" + hex.EncodeToString(suffix[:])
	fd, err := openat(d.dirfd, tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|openSafe, 0o600)
	if err != nil {
		return fmt.Errorf("backup: store archive: create temporary file: %w", err)
	}
	f := os.NewFile(uintptr(fd), "archive")
	fail := func(step string, err error) error {
		_ = f.Close()
		_ = unlinkat(d.dirfd, tmp)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return fmt.Errorf("backup: store archive: %s: %w", step, bareErr(err))
	}
	src := &trackingReader{r: ctxReader{ctx, r}}
	if _, err := io.CopyBuffer(struct{ io.Writer }{f}, src, make([]byte, copyBufferSize)); err != nil {
		if src.err != nil {
			// The source failed: say so with its own error.
			_ = f.Close()
			_ = unlinkat(d.dirfd, tmp)
			return src.err
		}
		return fail("write", err)
	}
	if err := f.Sync(); err != nil {
		return fail("fsync", err)
	}
	if err := f.Close(); err != nil {
		_ = unlinkat(d.dirfd, tmp)
		return fmt.Errorf("backup: store archive: close: %w", bareErr(err))
	}
	// rename(2) replaces the name itself: if a symbolic link was planted
	// under the archive's name, the link is replaced, not followed.
	if err := renameat(d.dirfd, tmp, name); err != nil {
		_ = unlinkat(d.dirfd, tmp)
		return fmt.Errorf("backup: store archive: rename into place: %w", err)
	}
	// Make the rename durable. Some network file systems do not support
	// fsync on a directory; that is not a failure of the backup.
	if err := ignoringEINTR(func() error { return syscall.Fsync(d.dirfd) }); err != nil &&
		!errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return fmt.Errorf("backup: store archive: fsync directory: %w", err)
	}
	return nil
}

// bareErr strips the placeholder path that os.File puts in its errors.
func bareErr(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// Get implements Destination. The archive must be a regular file: a symbolic
// link, a directory or a device under an archive's name is ErrUnsafePath.
func (d *DirDestination) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	if err := checkArchiveName(name); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := openat(d.dirfd, name, syscall.O_RDONLY|syscall.O_NONBLOCK|openSafe, 0)
	if err != nil {
		switch {
		case errors.Is(err, syscall.ENOENT):
			return nil, ErrNotFound
		case errors.Is(err, syscall.ELOOP):
			return nil, fmt.Errorf("%w: the archive is a symbolic link", ErrUnsafePath)
		}
		return nil, fmt.Errorf("backup: open archive: %w", err)
	}
	st, err := fstat(fd)
	if err != nil {
		closeFd(fd)
		return nil, fmt.Errorf("backup: open archive: %w", err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		closeFd(fd)
		return nil, fmt.Errorf("%w: the archive is not a regular file", ErrUnsafePath)
	}
	return os.NewFile(uintptr(fd), name), nil
}

// List implements Destination. Only regular files whose name is an archive
// name are returned; symbolic links, directories, temporary uploads and every
// other file are left out.
func (d *DirDestination) List(ctx context.Context) ([]Entry, error) {
	fd, err := openat(d.dirfd, ".", syscall.O_RDONLY|syscall.O_DIRECTORY|openSafe, 0)
	if err != nil {
		return nil, fmt.Errorf("backup: list destination: %w", err)
	}
	dir := os.NewFile(uintptr(fd), "destination")
	defer dir.Close()
	var entries []Entry
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		names, err := dir.Readdirnames(1024)
		for _, name := range names {
			if checkArchiveName(name) != nil {
				continue
			}
			// O_PATH|O_NOFOLLOW gives a handle on the name itself: a
			// symbolic link is seen as a link and skipped.
			pfd, err := openat(d.dirfd, name, oPath|openSafe, 0)
			if err != nil {
				continue
			}
			st, err := fstat(pfd)
			closeFd(pfd)
			if err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
				continue
			}
			if len(entries) >= maxListEntries {
				return nil, fmt.Errorf("backup: list destination: more than %d archives", maxListEntries)
			}
			entries = append(entries, Entry{Name: name, Size: st.Size,
				ModTime: time.Unix(int64(st.Mtim.Sec), int64(st.Mtim.Nsec))})
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("backup: list destination: %w", bareErr(err))
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

// Delete implements Destination. It removes the name itself: a symbolic link
// under an archive's name is removed, not followed.
func (d *DirDestination) Delete(ctx context.Context, name string) error {
	if err := checkArchiveName(name); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err := unlinkat(d.dirfd, name)
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("backup: delete archive: %w", err)
	}
	if err := ignoringEINTR(func() error { return syscall.Fsync(d.dirfd) }); err != nil &&
		!errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return fmt.Errorf("backup: delete archive: fsync directory: %w", err)
	}
	return nil
}
