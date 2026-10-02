package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"time"
)

// Limits applied by ExtractArchive when ExtractOptions leaves them at zero.
const (
	// DefaultMaxEntries is the default limit on the number of tar entries.
	DefaultMaxEntries = 1_000_000
	// DefaultMaxBytes is the default limit on the total size of the regular
	// files of an archive, once decompressed (256 GiB).
	DefaultMaxBytes = 256 << 30

	// maxPadding bounds the zero padding accepted after the end of the tar
	// stream.
	maxPadding = 1 << 20
	// maxID is the largest uid or gid restored; (uint32)-1 means "unchanged"
	// to chown and is not an owner.
	maxID = 0xFFFFFFFE
)

// ExtractOptions bound and tune ExtractArchive.
type ExtractOptions struct {
	// MaxEntries is the largest number of tar entries accepted, manifest
	// included. Zero means DefaultMaxEntries.
	MaxEntries int64
	// MaxBytes is the largest total size of regular files accepted, as
	// declared by the archive and before anything is written. Zero means
	// DefaultMaxBytes. Set it from the free space of the destination.
	MaxBytes int64
	// RestoreOwnership restores the numeric owner and group of every entry
	// (which needs root). When false everything belongs to the caller.
	RestoreOwnership bool

	// chown and lchown replace the system calls in tests.
	chown  func(fd, uid, gid int) error
	lchown func(dirfd int, name string, uid, gid int) error
}

// ExtractResult is what ExtractArchive restored.
type ExtractResult struct {
	Manifest Manifest
	Files    int64
	Dirs     int64
	Symlinks int64
	// Bytes is the total size of the regular files written.
	Bytes int64
}

// ExtractArchive reads gzip(tar) from r and restores it under destDir, which
// is created (mode 0700) if it does not exist. Each item of the manifest ends
// up under destDir/<item name>; manifest.json itself is returned, not written.
//
// The archive is treated as hostile:
//
//   - the first entry must be a valid manifest.json and every other entry must
//     be under one of its items;
//   - an entry name that is absolute, has a "..", "." or empty component, or is
//     too long or too deep is refused (ErrUnsafePath);
//   - only regular files, directories and symbolic links are accepted: a hard
//     link, a device node, a FIFO or anything else is refused
//     (ErrUnsupportedEntry);
//   - no symbolic link is ever followed: every component of every path is
//     opened relative to its parent with O_NOFOLLOW, so an entry that goes
//     through a link (one extracted earlier or one that was already there) is
//     refused (ErrUnsafePath) and nothing is written outside destDir;
//   - nothing is overwritten: an entry whose name exists is refused
//     (ErrExists), so destDir should be an empty directory;
//   - more than MaxEntries entries is ErrTooManyEntries and more than MaxBytes
//     of file content is ErrTooLarge, before the excess is written;
//   - setuid and setgid bits are dropped; owners are restored only with
//     RestoreOwnership.
//
// Modes and modification times are restored (not the times of symbolic links).
// Directories that the archive does not list are created with mode 0700.
//
// The whole input is read: after the tar stream only zero padding may follow.
// With a reader from NewDecryptReader this is what makes a truncated archive
// fail (ErrTruncated).
//
// On error destDir holds a partial restore, which the caller must discard.
// Files are not fsynced.
func ExtractArchive(ctx context.Context, r io.Reader, destDir string, opts ExtractOptions) (ExtractResult, error) {
	x := &extractor{ctx: ctx, opts: opts, buf: make([]byte, copyBufferSize)}
	if x.opts.MaxEntries <= 0 {
		x.opts.MaxEntries = DefaultMaxEntries
	}
	if x.opts.MaxBytes <= 0 {
		x.opts.MaxBytes = DefaultMaxBytes
	}
	if x.opts.chown == nil {
		x.opts.chown = func(fd, uid, gid int) error {
			return ignoringEINTR(func() error { return syscall.Fchown(fd, uid, gid) })
		}
	}
	if x.opts.lchown == nil {
		x.opts.lchown = func(dirfd int, name string, uid, gid int) error {
			return ignoringEINTR(func() error { return syscall.Fchownat(dirfd, name, uid, gid, atSymlinkNoFollow) })
		}
	}

	gz, err := gzip.NewReader(r)
	if err != nil {
		return x.res, readError(err)
	}
	tr := tar.NewReader(gz)
	if err := x.readManifest(tr); err != nil {
		return x.res, err
	}

	if err := os.Mkdir(destDir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return x.res, fmt.Errorf("backup: restore: create the destination directory: %w", err)
	}
	rootfd, err := openDir(destDir)
	if err != nil {
		return x.res, fmt.Errorf("backup: restore: open the destination directory: %w", err)
	}
	x.stack = []dirFrame{{fd: rootfd}}
	defer x.closeAll()

	for {
		if err := ctx.Err(); err != nil {
			return x.res, err
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if errors.Is(err, tar.ErrInsecurePath) {
				err = ErrUnsafePath
			}
			return x.res, readError(err)
		}
		x.entries++
		if x.entries > x.opts.MaxEntries {
			return x.res, ErrTooManyEntries
		}
		if err := x.entry(hdr, tr); err != nil {
			return x.res, err
		}
	}
	if err := x.unwind(1); err != nil {
		return x.res, err
	}
	if err := drainPadding(ctx, gz, x.buf); err != nil {
		return x.res, err
	}
	return x.res, nil
}

// streamErrors are the errors of a decrypting reader below the archive; they
// are reported as they are.
var streamErrors = []error{ErrKeyOrHeader, ErrCorrupt, ErrTruncated, ErrTrailingData, ErrChunkLength,
	context.Canceled, context.DeadlineExceeded}

// readError classifies an error met while reading the archive: an error of the
// encrypted stream or of the context is returned as it is, anything else means
// the content is not a valid archive.
func readError(err error) error {
	for _, target := range streamErrors {
		if errors.Is(err, target) {
			return err
		}
	}
	if errors.Is(err, ErrBadArchive) || errors.Is(err, ErrUnsafePath) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrBadArchive, err)
}

// drainPadding reads r to its end. Only zero bytes may remain, and not many.
func drainPadding(ctx context.Context, r io.Reader, buf []byte) error {
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := r.Read(buf)
		total += int64(n)
		if total > maxPadding || len(bytes.TrimLeft(buf[:n], "\x00")) != 0 {
			return fmt.Errorf("%w: data after the end of the archive", ErrBadArchive)
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return readError(err)
		}
	}
}

// dirFrame is one open directory on the path of the entry being restored.
type dirFrame struct {
	name string
	fd   int
	// meta is set when the archive has an entry for the directory: it is
	// applied when the directory is left, after its content was written.
	meta *dirMeta
}

type dirMeta struct {
	mode     uint32
	uid, gid int
	mtime    time.Time
}

type extractor struct {
	ctx     context.Context
	opts    ExtractOptions
	buf     []byte
	res     ExtractResult
	items   map[string]string // item name -> kind
	entries int64
	// declared is the sum of the sizes announced by the regular files so far.
	declared int64
	// stack[0] is destDir; stack[i] is the directory named stack[i].name
	// inside stack[i-1].
	stack []dirFrame
}

func (x *extractor) fail(name, item string, err error) error {
	for _, target := range streamErrors {
		if errors.Is(err, target) {
			return err
		}
	}
	return &EntryError{Op: "restore", Item: item, Name: name, Err: err}
}

func (x *extractor) readManifest(tr *tar.Reader) error {
	hdr, err := tr.Next()
	if err == io.EOF {
		return fmt.Errorf("%w: empty archive", ErrBadArchive)
	}
	if err != nil {
		return readError(err)
	}
	x.entries++
	if hdr.Typeflag != tar.TypeReg || hdr.Name != ManifestName {
		return fmt.Errorf("%w: the first entry is not %s", ErrBadArchive, ManifestName)
	}
	if hdr.Size <= 0 || hdr.Size > maxManifestBytes {
		return fmt.Errorf("%w: manifest size", ErrBadArchive)
	}
	raw, err := io.ReadAll(io.LimitReader(tr, maxManifestBytes+1))
	if err != nil {
		return readError(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return fmt.Errorf("%w: manifest: %v", ErrBadArchive, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: manifest: trailing data", ErrBadArchive)
	}
	if err := m.validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrBadArchive, err)
	}
	x.res.Manifest = m
	x.items = make(map[string]string, len(m.Items))
	for _, it := range m.Items {
		x.items[it.Name] = it.Kind
	}
	return nil
}

// splitEntryName validates an entry name and returns its components.
func splitEntryName(name string, isDir bool) ([]string, error) {
	if name == "" || len(name) > maxPathLen || strings.ContainsRune(name, 0) {
		return nil, fmt.Errorf("%w: empty, too long or with a NUL", ErrUnsafePath)
	}
	if name[0] == '/' {
		return nil, fmt.Errorf("%w: absolute path", ErrUnsafePath)
	}
	if isDir {
		name = strings.TrimSuffix(name, "/")
	}
	comps := strings.Split(name, "/")
	if len(comps) > maxDepth {
		return nil, fmt.Errorf("%w: too deep", ErrUnsafePath)
	}
	for _, c := range comps {
		switch {
		case c == "":
			return nil, fmt.Errorf("%w: empty path component", ErrUnsafePath)
		case c == "." || c == "..":
			return nil, fmt.Errorf("%w: \".\" or \"..\" in the path", ErrUnsafePath)
		case len(c) > maxNameLen:
			return nil, fmt.Errorf("%w: path component too long", ErrUnsafePath)
		}
	}
	return comps, nil
}

// itemOf returns the manifest item that the components are under, and how many
// components the item name has.
func (x *extractor) itemOf(comps []string) (item string, n int, ok bool) {
	p := ""
	for i, c := range comps {
		if i > 0 {
			p += "/"
		}
		p += c
		if len(p) > maxItemNameLen {
			break
		}
		if _, found := x.items[p]; found {
			return p, i + 1, true
		}
	}
	return "", 0, false
}

// entry restores one tar entry.
func (x *extractor) entry(hdr *tar.Header, tr *tar.Reader) error {
	switch hdr.Typeflag {
	case tar.TypeReg, tar.TypeDir, tar.TypeSymlink:
	case tar.TypeLink:
		return x.fail(hdr.Name, "", fmt.Errorf("%w: hard link", ErrUnsupportedEntry))
	case tar.TypeChar, tar.TypeBlock:
		return x.fail(hdr.Name, "", fmt.Errorf("%w: device node", ErrUnsupportedEntry))
	case tar.TypeFifo:
		return x.fail(hdr.Name, "", fmt.Errorf("%w: FIFO", ErrUnsupportedEntry))
	default:
		return x.fail(hdr.Name, "", fmt.Errorf("%w: type %q", ErrUnsupportedEntry, hdr.Typeflag))
	}
	isDir := hdr.Typeflag == tar.TypeDir
	comps, err := splitEntryName(hdr.Name, isDir)
	if err != nil {
		return x.fail(hdr.Name, "", err)
	}
	item, n, ok := x.itemOf(comps)
	if !ok {
		return x.fail(hdr.Name, "", fmt.Errorf("%w: entry outside the items of the manifest", ErrBadArchive))
	}
	if len(comps) == n && !isDir {
		return x.fail(hdr.Name, item, fmt.Errorf("%w: an item is a directory in the archive", ErrBadArchive))
	}
	if x.opts.RestoreOwnership && (hdr.Uid < 0 || hdr.Uid > maxID || hdr.Gid < 0 || hdr.Gid > maxID) {
		return x.fail(hdr.Name, item, fmt.Errorf("%w: owner out of range", ErrBadArchive))
	}

	switch hdr.Typeflag {
	case tar.TypeDir:
		err = x.dir(hdr, comps)
	case tar.TypeSymlink:
		err = x.symlink(hdr, comps)
	default:
		err = x.file(hdr, comps, tr)
	}
	if err != nil {
		return x.fail(hdr.Name, item, err)
	}
	return nil
}

// descend makes the open directory stack equal to destDir/comps..., leaving
// (and finishing) the directories that are not on that path and creating
// (mode 0700) the ones that do not exist. No component may be a symbolic
// link or anything but a directory.
func (x *extractor) descend(comps []string) error {
	common := 0
	for common < len(comps) && common+1 < len(x.stack) && x.stack[common+1].name == comps[common] {
		common++
	}
	if err := x.unwind(common + 1); err != nil {
		return err
	}
	for _, c := range comps[common:] {
		parent := x.stack[len(x.stack)-1].fd
		if err := mkdirat(parent, c, 0o700); err != nil && !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("create directory: %w", err)
		}
		fd, err := openat(parent, c, syscall.O_RDONLY|syscall.O_DIRECTORY|openSafe, 0)
		if err != nil {
			if isSymlinkErr(err) {
				return fmt.Errorf("%w: a component of the path is a symbolic link or not a directory", ErrUnsafePath)
			}
			return fmt.Errorf("open directory: %w", err)
		}
		x.stack = append(x.stack, dirFrame{name: c, fd: fd})
	}
	return nil
}

// unwind leaves directories until keep frames remain, applying to each the
// metadata of its entry, deepest first.
func (x *extractor) unwind(keep int) error {
	for len(x.stack) > keep {
		f := x.stack[len(x.stack)-1]
		x.stack = x.stack[:len(x.stack)-1]
		err := x.finishDir(f)
		closeFd(f.fd)
		if err != nil {
			return &EntryError{Op: "restore", Err: err}
		}
	}
	return nil
}

func (x *extractor) finishDir(f dirFrame) error {
	if f.meta == nil {
		return nil
	}
	if x.opts.RestoreOwnership {
		if err := x.opts.chown(f.fd, f.meta.uid, f.meta.gid); err != nil {
			return fmt.Errorf("set directory owner: %w", err)
		}
	}
	if err := ignoringEINTR(func() error { return syscall.Fchmod(f.fd, f.meta.mode) }); err != nil {
		return fmt.Errorf("set directory mode: %w", err)
	}
	if !f.meta.mtime.IsZero() {
		if err := futimens(f.fd, f.meta.mtime); err != nil {
			return fmt.Errorf("set directory time: %w", err)
		}
	}
	return nil
}

func (x *extractor) closeAll() {
	for _, f := range x.stack {
		closeFd(f.fd)
	}
	x.stack = nil
}

func (x *extractor) dir(hdr *tar.Header, comps []string) error {
	if err := x.descend(comps); err != nil {
		return err
	}
	// Permission bits and the sticky bit; never setuid or setgid.
	x.stack[len(x.stack)-1].meta = &dirMeta{
		mode: uint32(hdr.Mode) & 0o1777, uid: hdr.Uid, gid: hdr.Gid, mtime: hdr.ModTime,
	}
	x.res.Dirs++
	return nil
}

func (x *extractor) symlink(hdr *tar.Header, comps []string) error {
	target := hdr.Linkname
	if target == "" || len(target) > maxPathLen || strings.ContainsRune(target, 0) {
		return fmt.Errorf("%w: unusable link target", ErrBadArchive)
	}
	if err := x.descend(comps[:len(comps)-1]); err != nil {
		return err
	}
	parent := x.stack[len(x.stack)-1].fd
	name := comps[len(comps)-1]
	// The link is created as a link and never used here: a later entry that
	// tries to go through it is stopped by descend.
	if err := symlinkat(target, parent, name); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return ErrExists
		}
		return fmt.Errorf("create link: %w", err)
	}
	if x.opts.RestoreOwnership {
		if err := x.opts.lchown(parent, name, hdr.Uid, hdr.Gid); err != nil {
			return fmt.Errorf("set link owner: %w", err)
		}
	}
	x.res.Symlinks++
	return nil
}

// trackingReader remembers the error of the reader it wraps, so that a failed
// copy can be blamed on the right side.
type trackingReader struct {
	r   io.Reader
	err error
}

func (t *trackingReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil && err != io.EOF {
		t.err = err
	}
	return n, err
}

func (x *extractor) file(hdr *tar.Header, comps []string, tr *tar.Reader) error {
	if hdr.Size < 0 {
		return fmt.Errorf("%w: negative size", ErrBadArchive)
	}
	// The limit is checked on the announced size, before a byte is written.
	if hdr.Size > x.opts.MaxBytes-x.declared {
		return ErrTooLarge
	}
	x.declared += hdr.Size
	if err := x.descend(comps[:len(comps)-1]); err != nil {
		return err
	}
	parent := x.stack[len(x.stack)-1].fd
	name := comps[len(comps)-1]
	// O_EXCL: never write into something that exists, and never through a
	// symbolic link (O_EXCL does not follow one either).
	fd, err := openat(parent, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|openSafe, 0o600)
	if err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return ErrExists
		}
		return fmt.Errorf("create file: %w", err)
	}
	f := os.NewFile(uintptr(fd), "restored file")
	src := &trackingReader{r: ctxReader{x.ctx, tr}}
	n, err := io.CopyBuffer(struct{ io.Writer }{f}, src, x.buf)
	x.res.Bytes += n
	if err != nil {
		_ = f.Close()
		if src.err != nil {
			return readError(src.err)
		}
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return fmt.Errorf("write file: %w", err)
	}
	if n != hdr.Size {
		_ = f.Close()
		return fmt.Errorf("%w: short file", ErrBadArchive)
	}
	if x.opts.RestoreOwnership {
		if err := x.opts.chown(fd, hdr.Uid, hdr.Gid); err != nil {
			_ = f.Close()
			return fmt.Errorf("set file owner: %w", err)
		}
	}
	// Permission bits only: no setuid, setgid or sticky bit.
	if err := ignoringEINTR(func() error { return syscall.Fchmod(fd, uint32(hdr.Mode)&0o777) }); err != nil {
		_ = f.Close()
		return fmt.Errorf("set file mode: %w", err)
	}
	if !hdr.ModTime.IsZero() {
		if err := futimens(fd, hdr.ModTime); err != nil {
			_ = f.Close()
			return fmt.Errorf("set file time: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return fmt.Errorf("close file: %w", err)
	}
	x.res.Files++
	return nil
}
