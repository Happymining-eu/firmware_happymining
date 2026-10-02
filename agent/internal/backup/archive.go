package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Limits shared by the writer and the reader, so that a backup that could not
// be restored fails when it is made.
const (
	// ManifestName is the name of the first entry of every archive.
	ManifestName = "manifest.json"
	// ManifestFormat is the manifest format version written here.
	ManifestFormat = 1
	// MaxItems is the largest number of items in one archive.
	MaxItems = 512

	maxManifestBytes = 256 << 10
	maxItemNameLen   = 200
	// maxPathLen bounds an entry name and a link target, in bytes.
	maxPathLen = 4096
	// maxNameLen bounds one path component.
	maxNameLen = 255
	// maxDepth bounds the number of components of an entry name; the reader
	// keeps one open directory per component.
	maxDepth = 128
	// copyBufferSize is the buffer of file copies.
	copyBufferSize = 256 << 10
)

// Item kinds in the manifest.
const (
	KindDir  = "dir"
	KindFile = "file"
)

// Item is one thing to save: a directory (with everything under it) or a
// single regular file. It is stored under the logical name Name: the content
// of a directory as Name/..., a file as Name/<base name of Path>.
//
// Name is chosen by the caller and is what a restore sees; it is a relative
// path of components made of letters, digits, ".", "_" and "-" (for example
// "volumes/ollama/config"). Names are unique and none is inside another.
// Path is where the data is on this machine; it is not stored in the archive.
type Item struct {
	Name string
	Path string
}

// Manifest is the content of manifest.json, the first entry of every archive.
type Manifest struct {
	Format       int            `json:"format"`
	MachineID    string         `json:"machine_id"`
	CreatedAt    time.Time      `json:"created_at"`
	AgentVersion string         `json:"agent_version"`
	Items        []ManifestItem `json:"items"`
}

// ManifestItem is one item of a manifest.
type ManifestItem struct {
	Name string `json:"name"`
	// Kind is KindDir or KindFile.
	Kind string `json:"kind"`
}

// WriteOptions describe the archive being written; they go into the manifest.
type WriteOptions struct {
	// MachineID is the machine the archive belongs to (ValidMachineID).
	MachineID string
	// AgentVersion is the version of the software that made the archive.
	AgentVersion string
	// CreatedAt is the creation time; the zero value means now.
	CreatedAt time.Time
}

// WriteStats count what WriteArchive stored.
type WriteStats struct {
	Files    int64
	Dirs     int64
	Symlinks int64
	// Skipped counts sockets, device nodes, FIFOs and anything else that is
	// neither a regular file, a directory nor a symbolic link. They are left
	// out of the archive.
	Skipped int64
	// Vanished counts names that disappeared between the listing of their
	// directory and their turn.
	Vanished int64
	// Bytes is the total size of the regular files stored.
	Bytes int64
}

var (
	reItemComponent = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	reAgentVersion  = regexp.MustCompile(`^[A-Za-z0-9._+-]{0,64}$`)
)

// validItemName checks one item name.
func validItemName(name string) bool {
	if name == "" || len(name) > maxItemNameLen {
		return false
	}
	for i, c := range strings.Split(name, "/") {
		if !reItemComponent.MatchString(c) || c == "." || c == ".." {
			return false
		}
		if i == 0 && c == ManifestName {
			return false
		}
	}
	return true
}

// validate checks a manifest, written or read.
func (m Manifest) validate() error {
	if m.Format != ManifestFormat {
		return fmt.Errorf("manifest format %d is not supported", m.Format)
	}
	if !ValidMachineID(m.MachineID) {
		return errors.New("manifest machine id is not valid")
	}
	if !reAgentVersion.MatchString(m.AgentVersion) {
		return errors.New("manifest agent version is not valid")
	}
	if m.CreatedAt.IsZero() {
		return errors.New("manifest has no creation time")
	}
	if len(m.Items) > MaxItems {
		return fmt.Errorf("more than %d items", MaxItems)
	}
	names := make([]string, 0, len(m.Items))
	for _, it := range m.Items {
		if !validItemName(it.Name) {
			return errors.New("an item name is not valid")
		}
		if it.Kind != KindDir && it.Kind != KindFile {
			return errors.New("an item kind is not valid")
		}
		names = append(names, it.Name)
	}
	sort.Strings(names)
	for i := 1; i < len(names); i++ {
		if names[i] == names[i-1] {
			return fmt.Errorf("item name %q is used twice", names[i])
		}
	}
	for _, a := range names {
		for _, b := range names {
			if a != b && strings.HasPrefix(b, a+"/") {
				return fmt.Errorf("item %q is inside item %q", b, a)
			}
		}
	}
	return nil
}

// itemRoot is an item whose source was opened once and identified.
type itemRoot struct {
	item Item
	kind string
	dev  uint64
	ino  uint64
}

// WriteArchive writes gzip(tar) of items to w: first manifest.json, then every
// item in the order given, directories walked in name order.
//
// Regular files, directories and symbolic links are stored, with their mode
// bits, modification time and numeric owner and group. A symbolic link is
// stored as a link and never followed, in the middle of a path either: every
// name is opened relative to its already opened parent directory with
// O_NOFOLLOW. Sockets, device nodes and FIFOs are skipped and counted, without
// being opened. Hard-linked files are stored once per name. Extended
// attributes and ACLs are not stored.
//
// The item's own Path must be a real directory or a regular file, not a
// symbolic link. A source that cannot be read, or a file that shrinks while it
// is read, fails the whole archive: a backup with holes is not reported as a
// backup. Nothing is buffered beyond one copy buffer.
//
// WriteArchive does not close w. On error, what was written to w is not a
// complete archive and must be discarded.
func WriteArchive(ctx context.Context, w io.Writer, items []Item, opts WriteOptions) (WriteStats, error) {
	created := opts.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	created = created.UTC().Truncate(time.Second)
	if !ValidMachineID(opts.MachineID) {
		return WriteStats{}, fmt.Errorf("%w: machine id", ErrInvalidConfig)
	}
	if !reAgentVersion.MatchString(opts.AgentVersion) {
		return WriteStats{}, fmt.Errorf("%w: agent version", ErrInvalidConfig)
	}

	// Identify every source first: the manifest comes first in the archive
	// and says what each item is.
	roots := make([]itemRoot, 0, len(items))
	m := Manifest{Format: ManifestFormat, MachineID: opts.MachineID, CreatedAt: created,
		AgentVersion: opts.AgentVersion, Items: make([]ManifestItem, 0, len(items))}
	for _, it := range items {
		if !validItemName(it.Name) {
			return WriteStats{}, fmt.Errorf("%w: name %q", ErrInvalidItem, it.Name)
		}
		if !path.IsAbs(it.Path) || strings.ContainsRune(it.Path, 0) {
			return WriteStats{}, fmt.Errorf("%w: %q: the path must be absolute", ErrInvalidItem, it.Name)
		}
		fd, st, err := openSource(it.Path)
		if err != nil {
			return WriteStats{}, &EntryError{Op: "save", Item: it.Name, Name: it.Name, Err: err}
		}
		closeFd(fd)
		root := itemRoot{item: it, dev: uint64(st.Dev), ino: st.Ino}
		switch st.Mode & syscall.S_IFMT {
		case syscall.S_IFDIR:
			root.kind = KindDir
		case syscall.S_IFREG:
			root.kind = KindFile
			if base := path.Base(it.Path); len(it.Name)+1+len(base) > maxPathLen {
				return WriteStats{}, fmt.Errorf("%w: %q: the path is too long", ErrInvalidItem, it.Name)
			}
		default:
			return WriteStats{}, fmt.Errorf("%w: %q is neither a directory nor a regular file", ErrInvalidItem, it.Name)
		}
		roots = append(roots, root)
		m.Items = append(m.Items, ManifestItem{Name: it.Name, Kind: root.kind})
	}
	if err := m.validate(); err != nil {
		return WriteStats{}, fmt.Errorf("%w: %v", ErrInvalidItem, err)
	}
	manifest, err := json.Marshal(m)
	if err != nil {
		return WriteStats{}, fmt.Errorf("backup: encode manifest: %w", err)
	}
	if len(manifest) > maxManifestBytes {
		return WriteStats{}, fmt.Errorf("%w: the manifest is too large", ErrInvalidItem)
	}

	// Speed over ratio: plugins are stopped while their volumes are read, and
	// model files hardly compress.
	gz, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
	if err != nil {
		return WriteStats{}, fmt.Errorf("backup: gzip: %w", err)
	}
	a := &archiveWriter{ctx: ctx, tw: tar.NewWriter(gz), buf: make([]byte, copyBufferSize)}

	if err := a.tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg, Name: ManifestName, Size: int64(len(manifest)),
		Mode: 0o600, ModTime: created, Format: tar.FormatPAX,
	}); err != nil {
		return a.stats, fmt.Errorf("backup: write archive: %w", err)
	}
	if _, err := a.tw.Write(manifest); err != nil {
		return a.stats, fmt.Errorf("backup: write archive: %w", err)
	}
	for _, root := range roots {
		if err := a.addItem(root); err != nil {
			return a.stats, err
		}
	}
	if err := a.tw.Close(); err != nil {
		return a.stats, fmt.Errorf("backup: write archive: %w", err)
	}
	if err := gz.Close(); err != nil {
		return a.stats, fmt.Errorf("backup: write archive: %w", err)
	}
	return a.stats, nil
}

// openSource opens an item's own path for reading without following a symbolic
// link in its last component and without blocking on a FIFO.
func openSource(p string) (int, syscall.Stat_t, error) {
	var fd int
	err := ignoringEINTR(func() error {
		var e error
		fd, e = syscall.Open(p, syscall.O_RDONLY|syscall.O_NONBLOCK|openSafe, 0)
		return e
	})
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return -1, syscall.Stat_t{}, fmt.Errorf("%w: the source is a symbolic link", ErrInvalidItem)
		}
		return -1, syscall.Stat_t{}, fmt.Errorf("open source: %w", err)
	}
	st, err := fstat(fd)
	if err != nil {
		closeFd(fd)
		return -1, syscall.Stat_t{}, fmt.Errorf("stat source: %w", err)
	}
	return fd, st, nil
}

type archiveWriter struct {
	ctx   context.Context
	tw    *tar.Writer
	buf   []byte
	stats WriteStats
	item  string // name of the item being written, for errors
}

// fail wraps an error with the entry it is about.
func (a *archiveWriter) fail(name string, err error) error {
	var ee *EntryError
	if errors.As(err, &ee) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return &EntryError{Op: "save", Item: a.item, Name: name, Err: err}
}

func (a *archiveWriter) addItem(root itemRoot) error {
	a.item = root.item.Name
	fd, st, err := openSource(root.item.Path)
	if err != nil {
		return a.fail(root.item.Name, err)
	}
	if uint64(st.Dev) != root.dev || st.Ino != root.ino {
		closeFd(fd)
		return a.fail(root.item.Name, ErrSourceChanged)
	}
	if root.kind == KindFile {
		// writeFile closes fd.
		return a.writeFile(fd, st, root.item.Name+"/"+path.Base(root.item.Path))
	}
	defer closeFd(fd)
	if err := a.writeHeader(st, root.item.Name, ""); err != nil {
		return err
	}
	a.stats.Dirs++
	return a.walk(fd, root.item.Name, strings.Count(root.item.Name, "/")+1)
}

// header builds the tar header of one entry from its stat. Owners are
// numeric only: user and group names are not stored.
func header(st syscall.Stat_t, name, target string) *tar.Header {
	h := &tar.Header{
		Name:    name,
		Mode:    int64(st.Mode & 0o7777),
		Uid:     int(st.Uid),
		Gid:     int(st.Gid),
		ModTime: time.Unix(int64(st.Mtim.Sec), int64(st.Mtim.Nsec)),
		Format:  tar.FormatPAX,
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFDIR:
		h.Typeflag = tar.TypeDir
		h.Name = name + "/"
	case syscall.S_IFLNK:
		h.Typeflag = tar.TypeSymlink
		h.Linkname = target
	default:
		h.Typeflag = tar.TypeReg
		h.Size = st.Size
	}
	return h
}

func (a *archiveWriter) writeHeader(st syscall.Stat_t, name, target string) error {
	if err := a.tw.WriteHeader(header(st, name, target)); err != nil {
		return a.fail(name, fmt.Errorf("write archive: %w", err))
	}
	return nil
}

// walk stores the content of the directory dirfd, whose archive name is rel
// and which is depth components deep.
func (a *archiveWriter) walk(dirfd int, rel string, depth int) error {
	names, err := readDirNames(dirfd)
	if err != nil {
		return a.fail(rel, fmt.Errorf("read directory: %w", err))
	}
	for _, name := range names {
		if err := a.ctx.Err(); err != nil {
			return err
		}
		child := rel + "/" + name
		if len(child) > maxPathLen || len(name) > maxNameLen || depth+1 > maxDepth {
			return a.fail(child, fmt.Errorf("%w: the path is too long or too deep to be restored", ErrInvalidItem))
		}
		if err := a.addChild(dirfd, name, child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// addChild stores the entry name of the directory dirfd.
func (a *archiveWriter) addChild(dirfd int, name, rel string, depth int) error {
	// First a handle on the name itself, whatever it is: O_PATH opens no
	// device and waits on no FIFO, and with O_NOFOLLOW a symbolic link is
	// seen as a link.
	pfd, err := openat(dirfd, name, oPath|openSafe, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			a.stats.Vanished++
			return nil
		}
		return a.fail(rel, fmt.Errorf("open: %w", err))
	}
	st, err := fstat(pfd)
	if err != nil {
		closeFd(pfd)
		return a.fail(rel, fmt.Errorf("stat: %w", err))
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFLNK:
		target, err := readlinkFd(pfd)
		closeFd(pfd)
		if err != nil {
			return a.fail(rel, fmt.Errorf("read link: %w", err))
		}
		if target == "" || len(target) > maxPathLen {
			return a.fail(rel, fmt.Errorf("%w: unusable link target", ErrInvalidItem))
		}
		if err := a.writeHeader(st, rel, target); err != nil {
			return err
		}
		a.stats.Symlinks++
		return nil
	case syscall.S_IFDIR, syscall.S_IFREG:
		closeFd(pfd)
	default:
		closeFd(pfd)
		a.stats.Skipped++
		return nil
	}

	// A directory or a regular file: open it for reading, again without
	// following a link, and make sure it is still the same file.
	flags := syscall.O_RDONLY | syscall.O_NONBLOCK | openSafe
	if st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
		flags |= syscall.O_DIRECTORY
	}
	fd, err := openat(dirfd, name, flags, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			a.stats.Vanished++
			return nil
		}
		if isSymlinkErr(err) {
			return a.fail(rel, ErrSourceChanged)
		}
		return a.fail(rel, fmt.Errorf("open: %w", err))
	}
	st2, err := fstat(fd)
	if err != nil {
		closeFd(fd)
		return a.fail(rel, fmt.Errorf("stat: %w", err))
	}
	if st2.Dev != st.Dev || st2.Ino != st.Ino || st2.Mode&syscall.S_IFMT != st.Mode&syscall.S_IFMT {
		closeFd(fd)
		return a.fail(rel, ErrSourceChanged)
	}
	if st2.Mode&syscall.S_IFMT == syscall.S_IFREG {
		// writeFile closes fd.
		return a.writeFile(fd, st2, rel)
	}
	defer closeFd(fd)
	if err := a.writeHeader(st2, rel, ""); err != nil {
		return err
	}
	a.stats.Dirs++
	return a.walk(fd, rel, depth)
}

// writeFile stores the regular file fd (which it closes) as rel. Exactly the
// size seen by stat is stored: a file that grew is cut there, a file that
// shrank fails the archive.
func (a *archiveWriter) writeFile(fd int, st syscall.Stat_t, rel string) error {
	f := os.NewFile(uintptr(fd), "source")
	defer f.Close()
	if err := a.writeHeader(st, rel, ""); err != nil {
		return err
	}
	n, err := io.CopyBuffer(a.tw, io.LimitReader(ctxReader{a.ctx, f}, st.Size), a.buf)
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return a.fail(rel, fmt.Errorf("copy: %w", err))
	}
	if n != st.Size {
		return a.fail(rel, ErrSourceChanged)
	}
	a.stats.Files++
	a.stats.Bytes += n
	return nil
}

// readDirNames returns the names in the directory dirfd, sorted, without "."
// and "..". It reads through its own descriptor so that dirfd's position is
// not moved.
func readDirNames(dirfd int) ([]string, error) {
	fd, err := openat(dirfd, ".", syscall.O_RDONLY|syscall.O_DIRECTORY|openSafe, 0)
	if err != nil {
		return nil, err
	}
	d := os.NewFile(uintptr(fd), "directory")
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}
