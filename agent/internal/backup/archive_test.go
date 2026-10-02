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
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

var testCreated = time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC)

const testMachine = "0b6e3c1a-52f4-4f0e-9d0a-7c1f5a2b9e11"

func testWriteOptions() WriteOptions {
	return WriteOptions{MachineID: testMachine, AgentVersion: "0.2.0", CreatedAt: testCreated}
}

// --- building a source tree ------------------------------------------------------

func writeFile(t testing.TB, path string, data []byte, mode os.FileMode, mtime time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

// sourceTree builds a directory with every kind of thing an archive stores,
// and two kinds it must skip. It returns the directory and how many of each
// it holds below the directory itself.
type treeCounts struct {
	files, dirs, symlinks, special int64
	bytes                          int64
}

func sourceTree(t testing.TB) (string, treeCounts) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "volume")
	old := time.Date(2024, 3, 9, 8, 7, 6, 123456789, time.UTC)
	big := randomBytes(t, copyBufferSize+300<<10+17)
	longName := strings.Repeat("n", 180) + ".bin"
	files := map[string][]byte{
		"empty":                   nil,
		"hello.txt":               []byte("hello\n"),
		"big.bin":                 big,
		"dir one/file with space": []byte("spaces"),
		"dir one/deep/a/b/c/leaf": []byte("leaf"),
		"dir one/" + longName:     []byte("long name"),
		"unicode/été-文件.txt":      []byte("unicode"),
		"modes/script.sh":         []byte("#!/bin/sh\n"),
		"modes/private":           []byte("private"),
		"modes/setuid":            []byte("setuid"),
	}
	var c treeCounts
	for rel, data := range files {
		writeFile(t, filepath.Join(root, rel), data, 0o644, old.Add(time.Duration(len(data))*time.Second))
		c.files++
		c.bytes += int64(len(data))
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Chmod(filepath.Join(root, "modes/script.sh"), 0o755))
	must(os.Chmod(filepath.Join(root, "modes/private"), 0o600))
	must(os.Chmod(filepath.Join(root, "modes/setuid"), 0o755|os.ModeSetuid|os.ModeSetgid))
	must(os.Mkdir(filepath.Join(root, "emptydir"), 0o750))
	must(os.Mkdir(filepath.Join(root, "sticky"), 0o777))
	must(os.Chmod(filepath.Join(root, "sticky"), 0o777|os.ModeSticky))
	must(os.Mkdir(filepath.Join(root, "setgid-dir"), 0o755))
	must(os.Chmod(filepath.Join(root, "setgid-dir"), 0o755|os.ModeSetgid))

	links := map[string]string{
		"link-rel":          "hello.txt",
		"link-abs":          "/nonexistent/hm-backup-test/target",
		"link-dangling":     "nowhere/at/all",
		"link-dir":          "dir one",
		"dir one/link-up":   "../hello.txt",
		"link-outside-root": "../../..",
	}
	for rel, target := range links {
		must(os.Symlink(target, filepath.Join(root, rel)))
		c.symlinks++
	}
	must(syscall.Mkfifo(filepath.Join(root, "a-fifo"), 0o600))
	must(syscall.Mknod(filepath.Join(root, "dir one/a-socket"), syscall.S_IFSOCK|0o600, 0))
	c.special = 2
	// A device node needs privileges; add one when the test may.
	if err := syscall.Mknod(filepath.Join(root, "a-device"), syscall.S_IFCHR|0o600, 1<<8|3); err == nil {
		c.special++
	}

	// Directory times last: creating entries changes them.
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root {
				c.dirs++
			}
			return os.Chtimes(p, old, old.Add(time.Duration(len(p))*time.Minute))
		}
		return nil
	})
	must(err)
	return root, c
}

// listArchive reads a plaintext archive with the standard library and returns
// its entries.
func listArchive(t testing.TB, archive []byte) []*tar.Header {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var headers []*tar.Header
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return headers
		}
		if err != nil {
			t.Fatal(err)
		}
		headers = append(headers, h)
	}
}

func isSpecial(mode fs.FileMode) bool {
	return mode&(fs.ModeNamedPipe|fs.ModeSocket|fs.ModeDevice|fs.ModeCharDevice) != 0
}

// compareTrees checks that dst is src as a restore must leave it: same files,
// directories and links, same content, permissions and times; no special
// file; no setuid or setgid bit.
func compareTrees(t *testing.T, src, dst string) {
	t.Helper()
	seen := map[string]bool{}
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		si, err := os.Lstat(p)
		if err != nil {
			return err
		}
		di, err := os.Lstat(filepath.Join(dst, rel))
		if isSpecial(si.Mode()) {
			if err == nil {
				t.Errorf("%s: a special file was restored", rel)
			}
			return nil
		}
		seen[rel] = true
		if err != nil {
			t.Errorf("%s: missing after restore: %v", rel, err)
			return nil
		}
		if si.Mode().Type() != di.Mode().Type() {
			t.Errorf("%s: type %v, want %v", rel, di.Mode().Type(), si.Mode().Type())
			return nil
		}
		if di.Mode()&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
			t.Errorf("%s: restored with setuid or setgid: %v", rel, di.Mode())
		}
		switch {
		case si.Mode()&fs.ModeSymlink != 0:
			st, _ := os.Readlink(p)
			dt, _ := os.Readlink(filepath.Join(dst, rel))
			if st != dt {
				t.Errorf("%s: link target %q, want %q", rel, dt, st)
			}
			return nil
		case si.IsDir():
			if si.Mode().Perm() != di.Mode().Perm() || si.Mode()&fs.ModeSticky != di.Mode()&fs.ModeSticky {
				t.Errorf("%s: mode %v, want %v", rel, di.Mode(), si.Mode())
			}
		default:
			if si.Mode().Perm() != di.Mode().Perm() {
				t.Errorf("%s: mode %v, want %v", rel, di.Mode(), si.Mode())
			}
			a, _ := os.ReadFile(p)
			b, _ := os.ReadFile(filepath.Join(dst, rel))
			if !bytes.Equal(a, b) {
				t.Errorf("%s: content differs (%d and %d bytes)", rel, len(a), len(b))
			}
		}
		if !si.ModTime().Equal(di.ModTime()) {
			t.Errorf("%s: modification time %v, want %v", rel, di.ModTime(), si.ModTime())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(dst, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if rel, _ := filepath.Rel(dst, p); !seen[rel] {
			t.Errorf("%s: restored but not in the source", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// --- round trip -------------------------------------------------------------------

func TestArchiveRoundTrip(t *testing.T) {
	src, counts := sourceTree(t)
	single := filepath.Join(t.TempDir(), "applied.json")
	writeFile(t, single, []byte(`{"schema":1}`), 0o600, testCreated.Add(-time.Hour))
	items := []Item{
		{Name: "volumes/ollama/config", Path: src},
		{Name: "document", Path: single},
	}

	var archive bytes.Buffer
	stats, err := WriteArchive(context.Background(), &archive, items, testWriteOptions())
	if err != nil {
		t.Fatal(err)
	}
	want := WriteStats{Files: counts.files + 1, Dirs: counts.dirs + 1, Symlinks: counts.symlinks,
		Skipped: counts.special, Bytes: counts.bytes + int64(len(`{"schema":1}`))}
	if stats != want {
		t.Fatalf("stats %+v, want %+v", stats, want)
	}

	// What is in the archive, read with the standard library only.
	headers := listArchive(t, archive.Bytes())
	if headers[0].Name != "manifest.json" || headers[0].Typeflag != tar.TypeReg {
		t.Fatalf("the first entry is %q", headers[0].Name)
	}
	if int64(len(headers)) != 1+stats.Files+stats.Dirs+stats.Symlinks {
		t.Fatalf("%d entries for %+v", len(headers), stats)
	}
	for _, h := range headers[1:] {
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeDir, tar.TypeSymlink:
		default:
			t.Errorf("entry %q has type %q", h.Name, h.Typeflag)
		}
		if !strings.HasPrefix(h.Name, "volumes/ollama/config/") && h.Name != "document/applied.json" {
			t.Errorf("entry %q is outside its item", h.Name)
		}
		if strings.Contains(h.Name, "fifo") || strings.Contains(h.Name, "socket") || strings.Contains(h.Name, "device") {
			t.Errorf("special file %q was stored", h.Name)
		}
		if h.Uname != "" || h.Gname != "" {
			t.Errorf("entry %q stores owner names %q/%q", h.Name, h.Uname, h.Gname)
		}
		if h.Uid != os.Getuid() || h.Gid != os.Getgid() {
			t.Errorf("entry %q owner %d:%d", h.Name, h.Uid, h.Gid)
		}
	}
	if headers[1].Name != "volumes/ollama/config/" || headers[1].Typeflag != tar.TypeDir {
		t.Fatalf("the item's own directory is not the first entry of the item: %q", headers[1].Name)
	}

	dest := filepath.Join(t.TempDir(), "restore")
	res, err := ExtractArchive(context.Background(), bytes.NewReader(archive.Bytes()), dest, ExtractOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != stats.Files || res.Dirs != stats.Dirs || res.Symlinks != stats.Symlinks || res.Bytes != stats.Bytes {
		t.Fatalf("restored %+v, saved %+v", res, stats)
	}
	wantManifest := Manifest{Format: 1, MachineID: testMachine, CreatedAt: testCreated, AgentVersion: "0.2.0",
		Items: []ManifestItem{{Name: "volumes/ollama/config", Kind: KindDir}, {Name: "document", Kind: KindFile}}}
	if got, _ := json.Marshal(res.Manifest); string(got) != mustJSON(t, wantManifest) {
		t.Fatalf("manifest %s", got)
	}
	compareTrees(t, src, filepath.Join(dest, "volumes/ollama/config"))
	got, err := os.ReadFile(filepath.Join(dest, "document/applied.json"))
	if err != nil || string(got) != `{"schema":1}` {
		t.Fatalf("file item: %q, %v", got, err)
	}
	// manifest.json is returned, not written.
	if _, err := os.Lstat(filepath.Join(dest, "manifest.json")); !os.IsNotExist(err) {
		t.Fatalf("manifest.json was written: %v", err)
	}
	// Directories the archive does not list are private.
	for _, implicit := range []string{"", "volumes", "volumes/ollama", "document"} {
		fi, err := os.Lstat(filepath.Join(dest, implicit))
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("implicit directory %q: %v, %v", implicit, fi.Mode(), err)
		}
	}
}

func mustJSON(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestManifestIsTheContractsShape(t *testing.T) {
	src, _ := sourceTree(t)
	var archive bytes.Buffer
	if _, err := WriteArchive(context.Background(), &archive, []Item{{Name: "data", Path: src}}, testWriteOptions()); err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	if _, err := tr.Next(); err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(tr)
	const want = `{"format":1,"machine_id":"` + testMachine + `","created_at":"2026-10-02T03:00:00Z","agent_version":"0.2.0","items":[{"name":"data","kind":"dir"}]}`
	if string(raw) != want {
		t.Fatalf("manifest.json is\n%s\nwant\n%s", raw, want)
	}
}

func TestWriteArchiveIsDeterministic(t *testing.T) {
	src, _ := sourceTree(t)
	var a, b bytes.Buffer
	for _, out := range []*bytes.Buffer{&a, &b} {
		if _, err := WriteArchive(context.Background(), out, []Item{{Name: "data", Path: src}}, testWriteOptions()); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("two archives of the same tree at the same time differ")
	}
	names := []string{}
	for _, h := range listArchive(t, a.Bytes())[1:] {
		names = append(names, h.Name)
	}
	// Depth first, each directory in name order.
	if !sort.SliceIsSorted(names, func(i, j int) bool {
		return strings.ReplaceAll(names[i], "/", "\x00") < strings.ReplaceAll(names[j], "/", "\x00")
	}) {
		t.Fatalf("entries are not in a stable order: %q", names)
	}
}

func TestWriteArchiveNeverFollowsSymlinks(t *testing.T) {
	base := t.TempDir()
	secretDir := filepath.Join(base, "secret")
	writeFile(t, filepath.Join(secretDir, "shadow"), []byte("TOP-SECRET-CONTENT"), 0o600, testCreated)
	src := filepath.Join(base, "volume")
	writeFile(t, filepath.Join(src, "ok"), []byte("ok"), 0o644, testCreated)
	if err := os.Symlink(secretDir, filepath.Join(src, "to-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(secretDir, "shadow"), filepath.Join(src, "to-file")); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	stats, err := WriteArchive(context.Background(), &archive, []Item{{Name: "data", Path: src}}, testWriteOptions())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Symlinks != 2 || stats.Files != 1 {
		t.Fatalf("stats %+v", stats)
	}
	gz, _ := gzip.NewReader(bytes.NewReader(archive.Bytes()))
	plain, _ := io.ReadAll(gz)
	if bytes.Contains(plain, []byte("TOP-SECRET-CONTENT")) {
		t.Fatal("the content behind a symbolic link is in the archive")
	}
	for _, h := range listArchive(t, archive.Bytes()) {
		if strings.Contains(h.Name, "shadow") {
			t.Fatalf("a symbolic link to a directory was walked: %q", h.Name)
		}
		if strings.HasPrefix(h.Name, "data/to-") && (h.Typeflag != tar.TypeSymlink || !strings.HasPrefix(h.Linkname, secretDir)) {
			t.Fatalf("%q: type %q, target %q", h.Name, h.Typeflag, h.Linkname)
		}
	}

	// The item's own path may not be a symbolic link either.
	link := filepath.Join(base, "volume-link")
	if err := os.Symlink(src, link); err != nil {
		t.Fatal(err)
	}
	_, err = WriteArchive(context.Background(), io.Discard, []Item{{Name: "data", Path: link}}, testWriteOptions())
	if !errors.Is(err, ErrInvalidItem) {
		t.Fatalf("symlink as an item: %v", err)
	}
}

func TestWriteArchiveRefusesBadItems(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "f"), []byte("x"), 0o644, testCreated)
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	ok := Item{Name: "ok", Path: dir}
	for name, items := range map[string][]Item{
		"empty name":           {{Name: "", Path: dir}},
		"absolute name":        {{Name: "/abs", Path: dir}},
		"dot dot":              {{Name: "a/../b", Path: dir}},
		"dot":                  {{Name: "./a", Path: dir}},
		"double slash":         {{Name: "a//b", Path: dir}},
		"trailing slash":       {{Name: "a/", Path: dir}},
		"space":                {{Name: "a b", Path: dir}},
		"control character":    {{Name: "a\nb", Path: dir}},
		"manifest":             {{Name: "manifest.json", Path: dir}},
		"manifest as a prefix": {{Name: "manifest.json/x", Path: dir}},
		"too long":             {{Name: strings.Repeat("a/", 120) + "a", Path: dir}},
		"twice":                {ok, ok},
		"one inside another":   {ok, {Name: "ok/sub", Path: dir}},
		"relative path":        {{Name: "rel", Path: "relative/path"}},
		"empty path":           {{Name: "nopath", Path: ""}},
		"a fifo":               {{Name: "fifo", Path: fifo}},
	} {
		if _, err := WriteArchive(context.Background(), io.Discard, items, testWriteOptions()); !errors.Is(err, ErrInvalidItem) {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, err := WriteArchive(context.Background(), io.Discard, []Item{{Name: "gone", Path: filepath.Join(dir, "missing")}}, testWriteOptions())
	if !errors.Is(err, syscall.ENOENT) {
		t.Errorf("missing source: %v", err)
	}
	// The manifest's own fields.
	for name, opts := range map[string]WriteOptions{
		"machine id": {MachineID: "Not Valid", AgentVersion: "0.2.0", CreatedAt: testCreated},
		"no machine": {AgentVersion: "0.2.0", CreatedAt: testCreated},
		"version":    {MachineID: testMachine, AgentVersion: "0.2.0\nx", CreatedAt: testCreated},
	} {
		if _, err := WriteArchive(context.Background(), io.Discard, []Item{ok}, opts); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	items := make([]Item, MaxItems+1)
	for i := range items {
		items[i] = Item{Name: fmt.Sprintf("item-%d", i), Path: dir}
	}
	if _, err := WriteArchive(context.Background(), io.Discard, items, testWriteOptions()); !errors.Is(err, ErrInvalidItem) {
		t.Errorf("too many items: %v", err)
	}
}

func TestWriteArchiveFailsOnAShrinkingFileAndStopsOnCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	writeFile(t, path, []byte("0123456789"), 0o644, testCreated)

	// A file shorter than its stat said: the archive must not be padded or
	// silently shortened.
	fd, st, err := openSource(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Size = 100
	a := &archiveWriter{ctx: context.Background(), tw: tar.NewWriter(io.Discard), buf: make([]byte, 64), item: "data"}
	err = a.writeFile(fd, st, "data/f")
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("shrunk file: %v", err)
	}
	var ee *EntryError
	if !errors.As(err, &ee) || ee.Name != "data/f" || ee.Item != "data" || strings.Contains(err.Error(), "data/f") {
		t.Fatalf("entry error %+v / %v", ee, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := WriteArchive(ctx, io.Discard, []Item{{Name: "data", Path: dir}}, testWriteOptions()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}

	boom := errors.New("pipe closed")
	if _, err := WriteArchive(context.Background(), &failAfter{n: 0, err: boom}, []Item{{Name: "data", Path: dir}}, testWriteOptions()); !errors.Is(err, boom) {
		t.Fatalf("writer failure: %v", err)
	}
}

func TestWriteArchiveReportsUnreadableSources(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "ok"), []byte("x"), 0o644, testCreated)
	writeFile(t, filepath.Join(dir, "locked"), []byte("x"), 0o000, testCreated)
	_, err := WriteArchive(context.Background(), io.Discard, []Item{{Name: "data", Path: dir}}, testWriteOptions())
	if !errors.Is(err, syscall.EACCES) {
		t.Fatalf("an unreadable file must fail the backup: %v", err)
	}
	var ee *EntryError
	if !errors.As(err, &ee) || ee.Name != "data/locked" || strings.Contains(err.Error(), "locked") {
		t.Fatalf("entry error %+v / %v", ee, err)
	}
}

// --- hostile archives --------------------------------------------------------------

type tarEntry struct {
	hdr  tar.Header
	body []byte
}

func regEntry(name string, body []byte) tarEntry {
	return tarEntry{hdr: tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(body)), ModTime: testCreated}, body: body}
}

func dirEntry(name string) tarEntry {
	return tarEntry{hdr: tar.Header{Typeflag: tar.TypeDir, Name: name, Mode: 0o755, ModTime: testCreated}}
}

func linkEntry(name, target string) tarEntry {
	return tarEntry{hdr: tar.Header{Typeflag: tar.TypeSymlink, Name: name, Linkname: target, Mode: 0o777, ModTime: testCreated}}
}

func defaultManifest() []byte {
	b, _ := json.Marshal(Manifest{Format: 1, MachineID: testMachine, CreatedAt: testCreated, AgentVersion: "0.2.0",
		Items: []ManifestItem{{Name: "data", Kind: KindDir}}})
	return b
}

// craftArchive builds gzip(tar) by hand: manifest (nil for none) then entries.
func craftArchive(t testing.TB, manifest []byte, entries ...tarEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	if manifest != nil {
		entries = append([]tarEntry{regEntry("manifest.json", manifest)}, entries...)
	}
	for _, e := range entries {
		h := e.hdr
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatalf("craft %q: %v", h.Name, err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatalf("craft %q: %v", h.Name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// hostileDirs returns a destination that does not exist yet and its sibling
// "outside", which holds one file that must survive.
func hostileDirs(t *testing.T) (dest, outside string) {
	t.Helper()
	base := t.TempDir()
	dest, outside = filepath.Join(base, "dest"), filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(outside, "victim"), []byte("untouched"), 0o644, testCreated)
	return dest, outside
}

// hostile extracts archive into a fresh destination and returns the error
// together with the destination and its sibling "outside".
func hostile(t *testing.T, archive []byte, opts ExtractOptions) (dest, outside string, err error) {
	t.Helper()
	dest, outside = hostileDirs(t)
	_, err = ExtractArchive(context.Background(), bytes.NewReader(archive), dest, opts)
	return dest, outside, err
}

// untouched checks that nothing was created or changed outside dest.
func untouched(t *testing.T, name, outside string) {
	t.Helper()
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(outside, "victim"))
	if len(entries) != 1 || string(data) != "untouched" {
		t.Errorf("%s: the directory outside the destination was modified: %v, victim %q", name, entries, data)
	}
	siblings, _ := os.ReadDir(filepath.Dir(outside))
	if len(siblings) > 2 {
		t.Errorf("%s: something was created beside the destination: %v", name, siblings)
	}
}

func TestExtractRefusesUnsafePaths(t *testing.T) {
	for name, entry := range map[string]tarEntry{
		"absolute":             regEntry("/tmp/hm-backup-absolute-test", []byte("x")),
		"absolute under item":  regEntry("/data/x", []byte("x")),
		"dot dot first":        regEntry("../escape", []byte("x")),
		"dot dot inside":       regEntry("data/../../escape", []byte("x")),
		"dot dot back in":      regEntry("data/../data/x", []byte("x")),
		"dot dot last":         regEntry("data/sub/..", []byte("x")),
		"dot dot directory":    dirEntry("data/../../escape/"),
		"dot dot symlink name": linkEntry("data/../escape", "x"),
		"dot":                  regEntry("data/./x", []byte("x")),
		"empty component":      regEntry("data//x", []byte("x")),
		"too deep":             regEntry("data/"+strings.Repeat("d/", maxDepth)+"x", []byte("x")),
		"component too long":   regEntry("data/"+strings.Repeat("n", 256), []byte("x")),
	} {
		dest, outside, err := hostile(t, craftArchive(t, defaultManifest(), entry), ExtractOptions{})
		if !errors.Is(err, ErrUnsafePath) {
			t.Errorf("%s: %v", name, err)
		}
		untouched(t, name, outside)
		if _, err := os.Lstat(filepath.Join(filepath.Dir(dest), "escape")); !os.IsNotExist(err) {
			t.Errorf("%s: escaped", name)
		}
	}
	if _, err := os.Lstat("/tmp/hm-backup-absolute-test"); !os.IsNotExist(err) {
		t.Error("an absolute entry was written")
	}
}

func TestSplitEntryName(t *testing.T) {
	good := map[string][]string{
		"data":           {"data"},
		"data/a/b":       {"data", "a", "b"},
		"data/a b/é":     {"data", "a b", "é"},
		"data/...":       {"data", "..."},
		"data/..x/x..":   {"data", "..x", "x.."},
		"data/back\\up":  {"data", "back\\up"},
		"data/new\nline": {"data", "new\nline"},
	}
	for name, want := range good {
		got, err := splitEntryName(name, false)
		if err != nil || strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%q: %q, %v", name, got, err)
		}
	}
	if got, err := splitEntryName("data/dir/", true); err != nil || len(got) != 2 {
		t.Errorf("directory with a trailing slash: %q, %v", got, err)
	}
	for _, name := range []string{"", "/", "/a", "a//b", "a/", "..", "a/..", "../a", "a/../b", ".", "a/./b", "a\x00b",
		"a/" + strings.Repeat("x", 256), strings.Repeat("a/", 128) + "a", strings.Repeat("a", 5000)} {
		if _, err := splitEntryName(name, false); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("%q: %v", name, err)
		}
	}
	if _, err := splitEntryName("data/dir//", true); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("two trailing slashes: %v", err)
	}
}

func TestExtractNeverWritesThroughASymlink(t *testing.T) {
	for name, build := range map[string]func(outside string) []tarEntry{
		"absolute link then file": func(outside string) []tarEntry {
			return []tarEntry{dirEntry("data/"), linkEntry("data/link", outside), regEntry("data/link/pwned", []byte("x"))}
		},
		"relative link then file": func(string) []tarEntry {
			return []tarEntry{dirEntry("data/"), linkEntry("data/up", "../../outside"), regEntry("data/up/pwned", []byte("x"))}
		},
		"link then directory": func(outside string) []tarEntry {
			return []tarEntry{dirEntry("data/"), linkEntry("data/link", outside), dirEntry("data/link/newdir/")}
		},
		"link then link": func(outside string) []tarEntry {
			return []tarEntry{dirEntry("data/"), linkEntry("data/link", outside), linkEntry("data/link/l2", outside)}
		},
		"link then deep file": func(outside string) []tarEntry {
			return []tarEntry{dirEntry("data/"), linkEntry("data/link", outside), regEntry("data/link/a/b/c", []byte("x"))}
		},
		"link without a directory entry": func(outside string) []tarEntry {
			return []tarEntry{linkEntry("data/link", outside), regEntry("data/link/pwned", []byte("x"))}
		},
		// Inside the destination but outside the item.
		"link to the parent": func(string) []tarEntry {
			return []tarEntry{dirEntry("data/"), linkEntry("data/dot", ".."), regEntry("data/dot/pwned", []byte("x"))}
		},
		// A link that stays inside the item is not followed either.
		"link inside then file": func(string) []tarEntry {
			return []tarEntry{dirEntry("data/"), dirEntry("data/real/"), linkEntry("data/alias", "real"), regEntry("data/alias/x", []byte("x"))}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dest, outside := hostileDirs(t)
			archive := craftArchive(t, defaultManifest(), build(outside)...)
			_, err := ExtractArchive(context.Background(), bytes.NewReader(archive), dest, ExtractOptions{})
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("got %v", err)
			}
			untouched(t, name, outside)
			for _, written := range []string{"data/real/x", "pwned"} {
				if _, err := os.Lstat(filepath.Join(dest, written)); !os.IsNotExist(err) {
					t.Fatalf("%s was written through a symbolic link", written)
				}
			}
		})
	}

	// The item's own name may not be a link.
	dest, outside := hostileDirs(t)
	archive := craftArchive(t, defaultManifest(), linkEntry("data", outside), regEntry("data/pwned", []byte("x")))
	if _, err := ExtractArchive(context.Background(), bytes.NewReader(archive), dest, ExtractOptions{}); !errors.Is(err, ErrBadArchive) {
		t.Fatalf("item as a link: %v", err)
	}
	untouched(t, "item as a link", outside)
}

func TestExtractRefusesSymlinkedDestinationComponents(t *testing.T) {
	// Something that was in the destination before the restore.
	base := t.TempDir()
	dest, outside := filepath.Join(base, "dest"), filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dest, "data")); err != nil {
		t.Fatal(err)
	}
	archive := craftArchive(t, defaultManifest(), dirEntry("data/"), regEntry("data/pwned", []byte("x")))
	_, err := ExtractArchive(context.Background(), bytes.NewReader(archive), dest, ExtractOptions{})
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("got %v", err)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("written through a planted link: %v", entries)
	}
}

func TestExtractNeverOverwrites(t *testing.T) {
	// A symbolic link, then a regular file of the same name: the classic way
	// to write to the link's target.
	dest, outside, err := hostile(t, craftArchive(t, defaultManifest(),
		dirEntry("data/"), linkEntry("data/f", "../../outside/victim"), regEntry("data/f", []byte("overwritten"))), ExtractOptions{})
	if !errors.Is(err, ErrExists) {
		t.Fatalf("file over link: %v", err)
	}
	untouched(t, "file over link", outside)
	if fi, err := os.Lstat(filepath.Join(dest, "data/f")); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("the link was replaced: %v", err)
	}

	for name, entries := range map[string][]tarEntry{
		"file twice":     {regEntry("data/f", []byte("one")), regEntry("data/f", []byte("two"))},
		"link twice":     {linkEntry("data/l", "a"), linkEntry("data/l", "b")},
		"link over file": {regEntry("data/f", []byte("one")), linkEntry("data/f", "/nonexistent/hm-backup-test/victim")},
		"file over dir":  {dirEntry("data/d/"), regEntry("data/d", []byte("x"))},
	} {
		dest, _, err := hostile(t, craftArchive(t, defaultManifest(), entries...), ExtractOptions{})
		if !errors.Is(err, ErrExists) {
			t.Errorf("%s: %v", name, err)
		}
		if data, err := os.ReadFile(filepath.Join(dest, "data/f")); err == nil && string(data) != "one" {
			t.Errorf("%s: the first file was replaced: %q", name, data)
		}
	}

	// A file that was already in the destination.
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "data/f"), []byte("mine"), 0o600, testCreated)
	_, err = ExtractArchive(context.Background(), bytes.NewReader(craftArchive(t, defaultManifest(), regEntry("data/f", []byte("theirs")))), base, ExtractOptions{})
	if !errors.Is(err, ErrExists) {
		t.Fatalf("existing file: %v", err)
	}
	if data, _ := os.ReadFile(filepath.Join(base, "data/f")); string(data) != "mine" {
		t.Fatalf("an existing file was overwritten: %q", data)
	}
}

func TestExtractRefusesHardLinksDevicesAndOtherTypes(t *testing.T) {
	for name, hdr := range map[string]tar.Header{
		"hard link":           {Typeflag: tar.TypeLink, Name: "data/hl", Linkname: "data/f"},
		"hard link outside":   {Typeflag: tar.TypeLink, Name: "data/hl", Linkname: "/nonexistent/hm-backup-test/victim"},
		"hard link traversal": {Typeflag: tar.TypeLink, Name: "data/hl", Linkname: "../../outside/victim"},
		"character device":    {Typeflag: tar.TypeChar, Name: "data/null", Devmajor: 1, Devminor: 3},
		"block device":        {Typeflag: tar.TypeBlock, Name: "data/sda", Devmajor: 8, Devminor: 0},
		"fifo":                {Typeflag: tar.TypeFifo, Name: "data/fifo"},
		"contiguous file":     {Typeflag: tar.TypeCont, Name: "data/cont"},
		"global header":       {Typeflag: tar.TypeXGlobalHeader, Name: "data/g", PAXRecords: map[string]string{"comment": "x"}, Format: tar.FormatPAX},
	} {
		if hdr.Typeflag != tar.TypeXGlobalHeader {
			hdr.Mode, hdr.ModTime = 0o644, testCreated
		}
		archive := craftArchive(t, defaultManifest(), regEntry("data/f", []byte("content")), tarEntry{hdr: hdr})
		dest, outside, err := hostile(t, archive, ExtractOptions{})
		if !errors.Is(err, ErrUnsupportedEntry) {
			t.Errorf("%s: %v", name, err)
		}
		untouched(t, name, outside)
		for _, created := range []string{"data/hl", "data/null", "data/sda", "data/fifo", "data/cont"} {
			if _, err := os.Lstat(filepath.Join(dest, created)); !os.IsNotExist(err) {
				t.Errorf("%s: %s was created", name, created)
			}
		}
	}
}

func TestExtractEnforcesSizeAndEntryLimits(t *testing.T) {
	// Total size: the limit applies to what the archive announces, before a
	// byte of the offending file is written.
	kb := bytes.Repeat([]byte("k"), 1000)
	dest, _, err := hostile(t, craftArchive(t, defaultManifest(), regEntry("data/a", kb), regEntry("data/b", kb), regEntry("data/c", kb)),
		ExtractOptions{MaxBytes: 2500})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("total size: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "data/c")); !os.IsNotExist(err) {
		t.Fatal("the file beyond the limit was created")
	}
	if _, _, err := hostile(t, craftArchive(t, defaultManifest(), regEntry("data/a", kb), regEntry("data/b", kb)), ExtractOptions{MaxBytes: 2000}); err != nil {
		t.Fatalf("exactly at the limit: %v", err)
	}
	if _, _, err := hostile(t, craftArchive(t, defaultManifest(), regEntry("data/a", kb)), ExtractOptions{MaxBytes: 999}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("one file: %v", err)
	}

	// A compression bomb: 64 MiB of zeros in a few kilobytes of archive.
	bomb := craftArchive(t, defaultManifest(), regEntry("data/zeros", make([]byte, 64<<20)))
	if len(bomb) > 1<<20 {
		t.Fatalf("the bomb is %d bytes", len(bomb))
	}
	dest, _, err = hostile(t, bomb, ExtractOptions{MaxBytes: 1 << 20})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("bomb: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "data/zeros")); !os.IsNotExist(err) {
		t.Fatal("the bomb was written")
	}

	// Number of entries, manifest included.
	var many []tarEntry
	for i := 0; i < 10; i++ {
		many = append(many, regEntry(fmt.Sprintf("data/f%d", i), nil))
	}
	dest, _, err = hostile(t, craftArchive(t, defaultManifest(), many...), ExtractOptions{MaxEntries: 6})
	if !errors.Is(err, ErrTooManyEntries) {
		t.Fatalf("too many entries: %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(dest, "data")); len(entries) != 5 {
		t.Fatalf("%d files were written with a limit of 6 entries (one is the manifest)", len(entries))
	}
	if _, _, err := hostile(t, craftArchive(t, defaultManifest(), many...), ExtractOptions{MaxEntries: 11}); err != nil {
		t.Fatalf("exactly at the limit: %v", err)
	}

	// The defaults are in force when the options are left at zero.
	if DefaultMaxEntries != 1_000_000 || DefaultMaxBytes != 256<<30 {
		t.Fatal("defaults changed")
	}
	sparse := tarEntry{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "data/huge", Mode: 0o644, Size: DefaultMaxBytes + 1, ModTime: testCreated}}
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	m := defaultManifest()
	_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "manifest.json", Mode: 0o600, Size: int64(len(m))})
	_, _ = tw.Write(m)
	_ = tw.WriteHeader(&sparse.hdr) // announced, never delivered
	_ = tw.Flush()
	_ = gz.Close()
	if _, _, err := hostile(t, out.Bytes(), ExtractOptions{}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("default size limit: %v", err)
	}
}

func TestExtractDropsSetuidAndSetgid(t *testing.T) {
	entries := []tarEntry{
		{hdr: tar.Header{Typeflag: tar.TypeDir, Name: "data/", Mode: 0o2775, ModTime: testCreated}},
		{hdr: tar.Header{Typeflag: tar.TypeDir, Name: "data/tmp/", Mode: 0o1777, ModTime: testCreated}},
		{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "data/suid", Mode: 0o4755, Size: 1, ModTime: testCreated}, body: []byte("x")},
		{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "data/sgid", Mode: 0o2755, Size: 1, ModTime: testCreated}, body: []byte("x")},
		{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "data/all", Mode: 0o7777, Size: 1, ModTime: testCreated}, body: []byte("x")},
		{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "data/high-bits", Mode: 0o1004755, Size: 1, ModTime: testCreated}, body: []byte("x")},
	}
	dest, _, err := hostile(t, craftArchive(t, defaultManifest(), entries...), ExtractOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]fs.FileMode{
		"data":           fs.ModeDir | 0o775,
		"data/tmp":       fs.ModeDir | fs.ModeSticky | 0o777,
		"data/suid":      0o755,
		"data/sgid":      0o755,
		"data/all":       0o777,
		"data/high-bits": 0o755,
	} {
		fi, err := os.Lstat(filepath.Join(dest, rel))
		if err != nil || fi.Mode() != want {
			t.Errorf("%s: mode %v, want %v (%v)", rel, fi.Mode(), want, err)
		}
	}
}

type chownCall struct {
	name     string
	uid, gid int
}

func TestExtractRestoresOwnershipOnlyWhenAsked(t *testing.T) {
	own := func(h tar.Header, uid, gid int) tar.Header { h.Uid, h.Gid = uid, gid; return h }
	entries := []tarEntry{
		{hdr: own(dirEntry("data/").hdr, 1000, 1001)},
		{hdr: own(regEntry("data/f", []byte("x")).hdr, 1234, 5678), body: []byte("x")},
		{hdr: own(linkEntry("data/l", "f").hdr, 4321, 8765)},
	}
	archive := craftArchive(t, defaultManifest(), entries...)

	var calls []chownCall
	hooks := ExtractOptions{
		chown: func(fd, uid, gid int) error {
			calls = append(calls, chownCall{"fd", uid, gid})
			return nil
		},
		lchown: func(dirfd int, name string, uid, gid int) error {
			calls = append(calls, chownCall{name, uid, gid})
			return nil
		},
	}
	// Not asked: no chown at all, and the files belong to the caller.
	dest, _, err := hostile(t, archive, hooks)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Fatalf("ownership was changed without being asked: %v", calls)
	}
	for _, rel := range []string{"data", "data/f", "data/l"} {
		fi, err := os.Lstat(filepath.Join(dest, rel))
		if err != nil {
			t.Fatal(err)
		}
		if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) != os.Geteuid() || int(st.Gid) != os.Getegid() {
			t.Errorf("%s belongs to %d:%d", rel, st.Uid, st.Gid)
		}
	}

	// Asked: every entry gets its numeric owner; the link itself, not its
	// target; the directory last.
	hooks.RestoreOwnership = true
	if _, _, err := hostile(t, archive, hooks); err != nil {
		t.Fatal(err)
	}
	want := []chownCall{{"fd", 1234, 5678}, {"l", 4321, 8765}, {"fd", 1000, 1001}}
	if fmt.Sprint(calls) != fmt.Sprint(want) {
		t.Fatalf("chown calls %v, want %v", calls, want)
	}

	// A failing chown fails the restore (a restore that silently leaves
	// everything to root is not the one that was asked for).
	hooks.chown = func(int, int, int) error { return syscall.EPERM }
	if _, _, err := hostile(t, archive, hooks); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("failing chown: %v", err)
	}
	// Owners that are not owners.
	bad := craftArchive(t, defaultManifest(), tarEntry{hdr: own(regEntry("data/f", nil).hdr, -1, 0)})
	if _, _, err := hostile(t, bad, hooks); !errors.Is(err, ErrBadArchive) {
		t.Fatalf("uid -1: %v", err)
	}

	// The real system calls, with the only owner any user may set: itself.
	self := craftArchive(t, defaultManifest(),
		tarEntry{hdr: own(dirEntry("data/").hdr, os.Geteuid(), os.Getegid())},
		tarEntry{hdr: own(regEntry("data/f", []byte("x")).hdr, os.Geteuid(), os.Getegid()), body: []byte("x")},
		tarEntry{hdr: own(linkEntry("data/l", "/nonexistent/target").hdr, os.Geteuid(), os.Getegid())})
	if _, _, err := hostile(t, self, ExtractOptions{RestoreOwnership: true}); err != nil {
		t.Fatalf("real chown to self: %v", err)
	}
}

func TestExtractRefusesInvalidArchives(t *testing.T) {
	good := craftArchive(t, defaultManifest(), dirEntry("data/"), regEntry("data/f", []byte("x")))
	if _, _, err := hostile(t, good, ExtractOptions{}); err != nil {
		t.Fatal(err)
	}
	manifest := func(change func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(defaultManifest(), &m)
		change(m)
		b, _ := json.Marshal(m)
		return b
	}
	gzipOf := func(b []byte) []byte {
		var out bytes.Buffer
		gz := gzip.NewWriter(&out)
		_, _ = gz.Write(b)
		_ = gz.Close()
		return out.Bytes()
	}
	rawTar := func(a []byte) []byte {
		gz, _ := gzip.NewReader(bytes.NewReader(a))
		b, _ := io.ReadAll(gz)
		return b
	}
	for name, archive := range map[string][]byte{
		"empty input":             nil,
		"not gzip":                []byte("this is not an archive at all, just text"),
		"gzip of nothing":         gzipOf(nil),
		"gzip of text":            gzipOf([]byte("hello hello hello")),
		"truncated gzip":          good[:len(good)-10],
		"no manifest":             craftArchive(t, nil, dirEntry("data/"), regEntry("data/f", []byte("x"))),
		"manifest not first":      craftArchive(t, nil, dirEntry("data/"), regEntry("manifest.json", defaultManifest())),
		"manifest is a directory": craftArchive(t, nil, dirEntry("manifest.json/")),
		"manifest in a directory": craftArchive(t, nil, regEntry("x/manifest.json", defaultManifest())),
		"empty manifest":          craftArchive(t, []byte{}),
		"manifest not JSON":       craftArchive(t, []byte("not json")),
		"manifest too large":      craftArchive(t, append(defaultManifest(), bytes.Repeat([]byte(" "), maxManifestBytes)...)),
		"unknown manifest field":  craftArchive(t, manifest(func(m map[string]any) { m["extra"] = 1 })),
		"future format":           craftArchive(t, manifest(func(m map[string]any) { m["format"] = 2 })),
		"no format":               craftArchive(t, manifest(func(m map[string]any) { delete(m, "format") })),
		"bad machine id":          craftArchive(t, manifest(func(m map[string]any) { m["machine_id"] = "../x" })),
		"bad item name":           craftArchive(t, manifest(func(m map[string]any) { m["items"] = []any{map[string]any{"name": "../x", "kind": "dir"}} })),
		"bad item kind":           craftArchive(t, manifest(func(m map[string]any) { m["items"] = []any{map[string]any{"name": "data", "kind": "device"}} })),
		"item named twice": craftArchive(t, manifest(func(m map[string]any) {
			m["items"] = []any{map[string]any{"name": "data", "kind": "dir"}, map[string]any{"name": "data", "kind": "dir"}}
		})),
		"two JSON values":           craftArchive(t, append(defaultManifest(), defaultManifest()...)),
		"entry outside the items":   craftArchive(t, defaultManifest(), regEntry("other/f", []byte("x"))),
		"entry beside the item":     craftArchive(t, defaultManifest(), regEntry("data2/f", []byte("x"))),
		"second manifest":           craftArchive(t, defaultManifest(), regEntry("manifest.json", defaultManifest())),
		"item as a file":            craftArchive(t, defaultManifest(), regEntry("data", []byte("x"))),
		"empty link target":         craftArchive(t, defaultManifest(), linkEntry("data/l", "")),
		"data after the tar end":    gzipOf(append(rawTar(good), []byte("trailing garbage")...)),
		"too much padding":          gzipOf(append(rawTar(good), make([]byte, maxPadding+1)...)),
		"second gzip member (junk)": append(append([]byte(nil), good...), gzipOf([]byte("junk"))...),
		"bytes after the gzip end":  append(append([]byte(nil), good...), 0xde, 0xad),
	} {
		_, outside, err := hostile(t, archive, ExtractOptions{})
		if !errors.Is(err, ErrBadArchive) {
			t.Errorf("%s: %v", name, err)
		}
		untouched(t, name, outside)
	}
	// Zero padding after the end of the tar stream is what other tar
	// programs write, and is accepted.
	if _, _, err := hostile(t, gzipOf(append(rawTar(good), make([]byte, 10240)...)), ExtractOptions{}); err != nil {
		t.Fatalf("zero padding: %v", err)
	}
}

func TestExtractErrorsDoNotNameFiles(t *testing.T) {
	archive := craftArchive(t, defaultManifest(), regEntry("data/customer-invoice-2026.pdf", []byte("x")),
		tarEntry{hdr: tar.Header{Typeflag: tar.TypeLink, Name: "data/secret-project-name", Linkname: "data/x", ModTime: testCreated}})
	_, _, err := hostile(t, archive, ExtractOptions{})
	var ee *EntryError
	if !errors.As(err, &ee) || ee.Name != "data/secret-project-name" || ee.Op != "restore" {
		t.Fatalf("entry error %+v (%v)", ee, err)
	}
	if strings.Contains(err.Error(), "secret-project") || strings.Contains(err.Error(), "invoice") {
		t.Fatalf("the error text names a file: %v", err)
	}
}

func TestExtractStopsOnCancelAndPassesStreamErrors(t *testing.T) {
	archive := craftArchive(t, defaultManifest(), dirEntry("data/"), regEntry("data/f", randomBytes(t, 1<<20)))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ExtractArchive(ctx, bytes.NewReader(archive), filepath.Join(t.TempDir(), "d"), ExtractOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}

	// An archive cut by its encrypted envelope reports the envelope's error.
	key := mustNewKey(t)
	sealed := encryptWith(t, key, 4096, archive)
	for _, cutAt := range []int{len(sealed) - 1, len(sealed) / 2, HeaderSize + 4 + 4096 + 16} {
		r, err := NewDecryptReader(bytes.NewReader(sealed[:cutAt]), key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ExtractArchive(context.Background(), r, filepath.Join(t.TempDir(), "d"), ExtractOptions{})
		if !errors.Is(err, ErrTruncated) {
			t.Fatalf("cut at %d of %d: %v", cutAt, len(sealed), err)
		}
	}
	header, chunks := splitArchive(t, sealed)
	if len(chunks) < 3 {
		t.Fatalf("%d chunks", len(chunks))
	}
	chunks[1] = flip(chunks[1], 100)
	r, err := NewDecryptReader(bytes.NewReader(joinArchive(header, chunks...)), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractArchive(context.Background(), r, filepath.Join(t.TempDir(), "d"), ExtractOptions{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("altered chunk: %v", err)
	}
}

func TestExtractCreatesAPrivateDestinationAndRefusesAFile(t *testing.T) {
	base := t.TempDir()
	archive := craftArchive(t, defaultManifest(), dirEntry("data/"))
	dest := filepath.Join(base, "new")
	if _, err := ExtractArchive(context.Background(), bytes.NewReader(archive), dest, ExtractOptions{}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dest); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("destination mode %v, %v", fi.Mode(), err)
	}
	file := filepath.Join(base, "file")
	writeFile(t, file, []byte("x"), 0o600, testCreated)
	if _, err := ExtractArchive(context.Background(), bytes.NewReader(archive), file, ExtractOptions{}); err == nil {
		t.Fatal("a file was accepted as the destination")
	}
	if _, err := ExtractArchive(context.Background(), bytes.NewReader(archive), filepath.Join(base, "a/b/c"), ExtractOptions{}); err == nil {
		t.Fatal("a destination whose parent does not exist was accepted")
	}
	// A bad archive is refused before the destination is created.
	untouchedDest := filepath.Join(base, "never")
	if _, err := ExtractArchive(context.Background(), strings.NewReader("junk"), untouchedDest, ExtractOptions{}); err == nil {
		t.Fatal("junk accepted")
	}
	if _, err := os.Lstat(untouchedDest); !os.IsNotExist(err) {
		t.Fatal("the destination was created for an invalid archive")
	}
}
