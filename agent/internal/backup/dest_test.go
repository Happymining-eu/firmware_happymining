package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// --- archive names -----------------------------------------------------------------

func TestArchiveNameAndParse(t *testing.T) {
	paris := time.FixedZone("CEST", 2*3600)
	at := time.Date(2026, 10, 2, 5, 0, 7, 999_999_999, paris)
	name := ArchiveName(testMachine, at)
	if want := "hm-backup-" + testMachine + "-20261002T030007Z.hmbk"; name != want {
		t.Fatalf("ArchiveName = %q, want %q", name, want)
	}
	id, when, err := ParseArchiveName(name)
	if err != nil || id != testMachine || !when.Equal(time.Date(2026, 10, 2, 3, 0, 7, 0, time.UTC)) {
		t.Fatalf("ParseArchiveName: %q, %v, %v", id, when, err)
	}
	// Machine ids with dashes and digits parse to the whole id.
	for _, id := range []string{"a", "m1", "abc-def", "abc-20261002", "0b6e3c1a", strings.Repeat("a", 64), "a-b-c-d-e"} {
		got, _, err := ParseArchiveName(ArchiveName(id, at))
		if err != nil || got != id {
			t.Errorf("machine id %q: %q, %v", id, got, err)
		}
		if !ValidMachineID(id) {
			t.Errorf("%q is not a valid machine id", id)
		}
	}
	// What ArchiveName cannot make valid does not parse.
	for _, id := range []string{"", "-a", "a-", "A", "a_b", "a b", "a/b", "../a", "a.b", strings.Repeat("a", 65), "é", "a\n"} {
		if ValidMachineID(id) {
			t.Errorf("%q accepted as a machine id", id)
		}
		if _, _, err := ParseArchiveName(ArchiveName(id, at)); !errors.Is(err, ErrInvalidName) {
			t.Errorf("machine id %q gave a name that parses: %v", id, err)
		}
	}
	if _, _, err := ParseArchiveName(ArchiveName("m1", time.Date(12026, 1, 1, 0, 0, 0, 0, time.UTC))); !errors.Is(err, ErrInvalidName) {
		t.Errorf("year 12026: %v", err)
	}
	good := "hm-backup-m1-20261002T030000Z.hmbk"
	for _, bad := range []string{
		"", "x", "hm-backup", good + " ", " " + good, good + "\n", "x" + good, good + ".tmp",
		"." + good + ".tmp-0a1b2c", "dir/" + good, "../" + good, good + "/..", "/" + good,
		"hm-backup--20261002T030000Z.hmbk", "hm-backup-m1-20261002T030000Z.HMBK", "HM-BACKUP-m1-20261002T030000Z.hmbk",
		"hm-backup-m1-20261002t030000z.hmbk", "hm-backup-m1-20261002T030000.hmbk", "hm-backup-m1-2026-10-02T03:00:00Z.hmbk",
		"hm-backup-m1-20261302T030000Z.hmbk", "hm-backup-m1-20260230T030000Z.hmbk", "hm-backup-m1-20261002T250000Z.hmbk",
		"hm-backup-m1-20261002T036000Z.hmbk", "hm-backup-M1-20261002T030000Z.hmbk", "hm-backup-m1-20261002T030000Z.hmbk\x00",
		"hm-backup-m1_20261002T030000Z.hmbk", "hm-backup-m1-20261002T030000Z-20261002T030000Z.hmbk.hmbk",
	} {
		if _, _, err := ParseArchiveName(bad); !errors.Is(err, ErrInvalidName) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// --- an in-memory destination for the tests of Prune and Run ---------------------

type memDest struct {
	mu       sync.Mutex
	objects  map[string][]byte
	extra    []Entry // returned by List in addition to the objects
	deleted  []string
	putErr   error
	delErr   map[string]error
	listErr  error
	shortPut bool // return nil without reading everything
}

func newMemDest() *memDest { return &memDest{objects: map[string][]byte{}} }

func (m *memDest) Put(_ context.Context, name string, r io.Reader) error {
	if err := checkArchiveName(name); err != nil {
		return err
	}
	if m.shortPut {
		_, _ = io.CopyN(io.Discard, r, 10)
		return nil
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if m.putErr != nil {
		return m.putErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[name] = data
	return nil
}

func (m *memDest) Get(_ context.Context, name string) (io.ReadCloser, error) {
	if err := checkArchiveName(name); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objects[name]
	if !ok {
		return nil, ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m *memDest) List(context.Context) ([]Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listErr != nil {
		return nil, m.listErr
	}
	entries := append([]Entry(nil), m.extra...)
	for name, data := range m.objects {
		entries = append(entries, Entry{Name: name, Size: int64(len(data))})
	}
	return entries, nil
}

func (m *memDest) Delete(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleted = append(m.deleted, name)
	if err := m.delErr[name]; err != nil {
		return err
	}
	delete(m.objects, name)
	return nil
}

func (m *memDest) names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.objects))
	for name := range m.objects {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// --- Prune -------------------------------------------------------------------------

func day(d int) time.Time { return time.Date(2026, 9, d, 3, 0, 0, 0, time.UTC) }

func TestPruneKeepsTheNewestAndIgnoresEverythingElse(t *testing.T) {
	const mine, other, longer = "machine-a", "machine-b", "machine-a-2"
	dest := newMemDest()
	// Seven archives of this machine, stored in no particular order.
	for _, d := range []int{5, 1, 7, 3, 2, 6, 4} {
		dest.objects[ArchiveName(mine, day(d))] = []byte("a")
	}
	// Other machines, including one whose id starts with this one's.
	foreign := []string{
		ArchiveName(other, day(1)), ArchiveName(other, day(2)),
		ArchiveName(longer, day(1)), ArchiveName(longer, day(2)), ArchiveName(longer, day(3)), ArchiveName(longer, day(4)),
	}
	for _, name := range foreign {
		dest.objects[name] = []byte("b")
	}
	// A destination that lists things that are not archives must not get
	// them deleted either.
	dest.extra = []Entry{
		{Name: "notes.txt"}, {Name: "../../victim"}, {Name: ""}, {Name: "." + ArchiveName(mine, day(1)) + ".tmp-00ff"},
		{Name: ArchiveName(mine, day(1)) + ".bak"}, {Name: "hm-backup-machine-a-20260931T030000Z.hmbk"},
		{Name: "sub/" + ArchiveName(mine, day(1))}, {Name: strings.ToUpper(ArchiveName(mine, day(1)))},
		// The same archive listed twice counts once.
		{Name: ArchiveName(mine, day(7))},
	}

	deleted, err := Prune(context.Background(), dest, mine, 3)
	if err != nil {
		t.Fatal(err)
	}
	wantDeleted := []string{ArchiveName(mine, day(1)), ArchiveName(mine, day(2)), ArchiveName(mine, day(3)), ArchiveName(mine, day(4))}
	if fmt.Sprint(deleted) != fmt.Sprint(wantDeleted) || fmt.Sprint(dest.deleted) != fmt.Sprint(wantDeleted) {
		t.Fatalf("deleted %v (Delete calls %v), want %v", deleted, dest.deleted, wantDeleted)
	}
	want := append([]string{ArchiveName(mine, day(5)), ArchiveName(mine, day(6)), ArchiveName(mine, day(7))}, foreign...)
	sort.Strings(want)
	if fmt.Sprint(dest.names()) != fmt.Sprint(want) {
		t.Fatalf("left %v, want %v", dest.names(), want)
	}

	// Nothing more to delete.
	if deleted, err := Prune(context.Background(), dest, mine, 3); err != nil || len(deleted) != 0 {
		t.Fatalf("second prune: %v, %v", deleted, err)
	}
	if deleted, err := Prune(context.Background(), dest, mine, 365); err != nil || len(deleted) != 0 {
		t.Fatalf("keep 365: %v, %v", deleted, err)
	}
	if deleted, err := Prune(context.Background(), dest, "machine-without-archives", 1); err != nil || len(deleted) != 0 {
		t.Fatalf("unknown machine: %v, %v", deleted, err)
	}
	// keep 1 keeps the newest.
	if _, err := Prune(context.Background(), dest, mine, 1); err != nil {
		t.Fatal(err)
	}
	if _, ok := dest.objects[ArchiveName(mine, day(7))]; !ok || len(dest.objects) != 1+len(foreign) {
		t.Fatalf("keep 1 left %v", dest.names())
	}
}

func TestPruneRefusesBadArguments(t *testing.T) {
	dest := newMemDest()
	for d := 1; d <= 3; d++ {
		dest.objects[ArchiveName("m1", day(d))] = nil
	}
	for name, call := range map[string]func() ([]string, error){
		"keep 0":         func() ([]string, error) { return Prune(context.Background(), dest, "m1", 0) },
		"keep negative":  func() ([]string, error) { return Prune(context.Background(), dest, "m1", -1) },
		"no machine":     func() ([]string, error) { return Prune(context.Background(), dest, "", 1) },
		"bad machine":    func() ([]string, error) { return Prune(context.Background(), dest, "../x", 1) },
		"no destination": func() ([]string, error) { return Prune(context.Background(), nil, "m1", 1) },
	} {
		deleted, err := call()
		if !errors.Is(err, ErrInvalidConfig) || len(deleted) != 0 {
			t.Errorf("%s: %v, %v", name, deleted, err)
		}
	}
	if len(dest.objects) != 3 || len(dest.deleted) != 0 {
		t.Fatalf("something was deleted: %v", dest.deleted)
	}
}

func TestPruneStopsAtTheFirstFailure(t *testing.T) {
	dest := newMemDest()
	for d := 1; d <= 5; d++ {
		dest.objects[ArchiveName("m1", day(d))] = nil
	}
	boom := errors.New("read-only share")
	dest.delErr = map[string]error{ArchiveName("m1", day(2)): boom}
	deleted, err := Prune(context.Background(), dest, "m1", 1)
	if !errors.Is(err, boom) || fmt.Sprint(deleted) != fmt.Sprint([]string{ArchiveName("m1", day(1))}) {
		t.Fatalf("deleted %v, error %v", deleted, err)
	}
	if len(dest.objects) != 4 {
		t.Fatalf("left %v", dest.names())
	}

	dest.listErr = errors.New("unreachable")
	if deleted, err := Prune(context.Background(), dest, "m1", 1); !errors.Is(err, dest.listErr) || deleted != nil {
		t.Fatalf("list failure: %v, %v", deleted, err)
	}
	dest.listErr = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Prune(ctx, dest, "m1", 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}

// --- DirDestination ------------------------------------------------------------------

func openDirDest(t *testing.T, root, subpath string) *DirDestination {
	t.Helper()
	d, err := OpenDirDestination(root, subpath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestDirDestinationRoundTrip(t *testing.T) {
	root := t.TempDir()
	d := openDirDest(t, root, "happymining/backups")
	dir := filepath.Join(root, "happymining", "backups")
	if d.Path() != dir {
		t.Fatalf("Path %q", d.Path())
	}
	for _, p := range []string{filepath.Join(root, "happymining"), dir} {
		if fi, err := os.Lstat(p); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v, %v", p, fi, err)
		}
	}
	ctx := context.Background()
	if entries, err := d.List(ctx); err != nil || len(entries) != 0 {
		t.Fatalf("empty list: %v, %v", entries, err)
	}
	first, second := ArchiveName("m1", day(1)), ArchiveName("m1", day(2))
	content := randomBytes(t, 3*copyBufferSize+11)
	if err := d.Put(ctx, second, bytes.NewReader([]byte("second"))); err != nil {
		t.Fatal(err)
	}
	if err := d.Put(ctx, first, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	if got := dirNames(t, dir); fmt.Sprint(got) != fmt.Sprint([]string{first, second}) {
		t.Fatalf("directory holds %v (a temporary file was left?)", got)
	}
	if fi, _ := os.Lstat(filepath.Join(dir, first)); fi.Mode() != 0o600 {
		t.Fatalf("archive mode %v", fi.Mode())
	}
	entries, err := d.List(ctx)
	if err != nil || len(entries) != 2 || entries[0].Name != first || entries[1].Name != second ||
		entries[0].Size != int64(len(content)) || entries[1].Size != 6 || entries[0].ModTime.IsZero() {
		t.Fatalf("list %+v, %v", entries, err)
	}
	rc, err := d.Get(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if !bytes.Equal(got, content) {
		t.Fatal("content differs")
	}
	// Put replaces an archive of the same name.
	if err := d.Put(ctx, first, strings.NewReader("replaced")); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, first)); string(data) != "replaced" {
		t.Fatalf("after replace: %q", data)
	}
	if err := d.Delete(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Get(ctx, first); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete: %v", err)
	}
	if err := d.Delete(ctx, first); err != nil {
		t.Fatalf("deleting what is not there: %v", err)
	}
	if got := dirNames(t, dir); fmt.Sprint(got) != fmt.Sprint([]string{second}) {
		t.Fatalf("directory holds %v", got)
	}

	// Opening again finds the same archives.
	again := openDirDest(t, root, "happymining/backups")
	if entries, err := again.List(ctx); err != nil || len(entries) != 1 {
		t.Fatalf("reopened: %v, %v", entries, err)
	}
	// Prune works on a real directory.
	for dd := 3; dd <= 6; dd++ {
		if err := d.Put(ctx, ArchiveName("m1", day(dd)), strings.NewReader("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "family-photos.zip"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	deleted, err := Prune(ctx, d, "m1", 2)
	if err != nil || len(deleted) != 3 {
		t.Fatalf("prune: %v, %v", deleted, err)
	}
	if got := dirNames(t, dir); fmt.Sprint(got) != fmt.Sprint([]string{"family-photos.zip", ArchiveName("m1", day(5)), ArchiveName("m1", day(6))}) {
		t.Fatalf("after prune: %v", got)
	}
}

func TestDirDestinationFailedPutLeavesNothing(t *testing.T) {
	root := t.TempDir()
	d := openDirDest(t, root, "")
	name := ArchiveName("m1", day(1))
	ctx := context.Background()

	// The source fails half-way: no archive, no temporary file, and the
	// source's own error comes back.
	src := io.MultiReader(bytes.NewReader(randomBytes(t, 2*copyBufferSize)), failingReader{})
	if err := d.Put(ctx, name, src); !errors.Is(err, errInput) {
		t.Fatalf("failing source: %v", err)
	}
	if got := dirNames(t, root); len(got) != 0 {
		t.Fatalf("left behind: %v", got)
	}

	// An existing archive survives a failed replacement.
	if err := d.Put(ctx, name, strings.NewReader("good")); err != nil {
		t.Fatal(err)
	}
	if err := d.Put(ctx, name, io.MultiReader(strings.NewReader("half"), failingReader{})); !errors.Is(err, errInput) {
		t.Fatalf("failing replacement: %v", err)
	}
	if data, _ := os.ReadFile(filepath.Join(root, name)); string(data) != "good" || len(dirNames(t, root)) != 1 {
		t.Fatalf("after a failed replacement: %q, %v", data, dirNames(t, root))
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	other := ArchiveName("m1", day(2))
	if err := d.Put(cancelled, other, strings.NewReader("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
	// Cancelled while copying.
	ctx2, cancel2 := context.WithCancel(ctx)
	err := d.Put(ctx2, other, readerFunc(func(p []byte) (int, error) {
		cancel2()
		return copy(p, "data"), nil
	}))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled while copying: %v", err)
	}
	if got := dirNames(t, root); len(got) != 1 {
		t.Fatalf("left behind: %v", got)
	}
}

type readerFunc func(p []byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func TestDirDestinationTakesArchiveNamesOnly(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "share")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(base, "victim"), []byte("untouched"), 0o644, testCreated)
	writeFile(t, filepath.Join(root, "notes.txt"), []byte("notes"), 0o644, testCreated)
	d := openDirDest(t, root, "")
	ctx := context.Background()
	for _, name := range []string{
		// An absolute name points at the victim itself: the test never names
		// a real system file, so a regression cannot damage the machine it runs on.
		"", ".", "..", "notes.txt", "../victim", filepath.Join(base, "victim"), "sub/" + ArchiveName("m1", day(1)),
		ArchiveName("m1", day(1)) + "/../../victim", "." + ArchiveName("m1", day(1)) + ".tmp-00", "hm-backup-m1.hmbk",
	} {
		if err := d.Put(ctx, name, strings.NewReader("x")); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Put %q: %v", name, err)
		}
		if _, err := d.Get(ctx, name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Get %q: %v", name, err)
		}
		if err := d.Delete(ctx, name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Delete %q: %v", name, err)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(base, "victim")); string(data) != "untouched" {
		t.Fatal("a file outside the directory was changed")
	}
	if data, _ := os.ReadFile(filepath.Join(root, "notes.txt")); string(data) != "notes" {
		t.Fatal("a foreign file in the directory was changed")
	}
	if got := dirNames(t, root); len(got) != 1 {
		t.Fatalf("directory holds %v", got)
	}
	// Foreign files are not listed.
	if entries, err := d.List(ctx); err != nil || len(entries) != 0 {
		t.Fatalf("list %v, %v", entries, err)
	}
}

func TestDirDestinationIgnoresPlantedSymlinks(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "share")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(base, "victim")
	writeFile(t, victim, []byte("untouched"), 0o644, testCreated)
	d := openDirDest(t, root, "")
	ctx := context.Background()

	// Someone with access to the share plants links and oddities under names
	// that look like archives.
	link := ArchiveName("m1", day(1))
	if err := os.Symlink(victim, filepath.Join(root, link)); err != nil {
		t.Fatal(err)
	}
	dangling := ArchiveName("m1", day(2))
	if err := os.Symlink(filepath.Join(base, "created-through-link"), filepath.Join(root, dangling)); err != nil {
		t.Fatal(err)
	}
	asDir := ArchiveName("m1", day(3))
	if err := os.Mkdir(filepath.Join(root, asDir), 0o755); err != nil {
		t.Fatal(err)
	}
	asFifo := ArchiveName("m1", day(4))
	if err := syscall.Mkfifo(filepath.Join(root, asFifo), 0o644); err != nil {
		t.Fatal(err)
	}
	real := ArchiveName("m1", day(5))
	if err := d.Put(ctx, real, strings.NewReader("real")); err != nil {
		t.Fatal(err)
	}

	// Listed: the real archive only.
	entries, err := d.List(ctx)
	if err != nil || len(entries) != 1 || entries[0].Name != real {
		t.Fatalf("list %+v, %v", entries, err)
	}
	// Read: never through a link, never a directory, and a FIFO does not
	// block.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, name := range []string{link, dangling, asDir, asFifo} {
			rc, err := d.Get(ctx, name)
			if !errors.Is(err, ErrUnsafePath) {
				t.Errorf("Get %s: %v", name, err)
			}
			if rc != nil {
				data, _ := io.ReadAll(io.LimitReader(rc, 64))
				_ = rc.Close()
				t.Errorf("Get %s returned content %q", name, data)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Get blocked on a FIFO")
	}

	// Prune sees one archive: nothing to delete, and the links stay.
	if deleted, err := Prune(ctx, d, "m1", 1); err != nil || len(deleted) != 0 {
		t.Fatalf("prune: %v, %v", deleted, err)
	}

	// Written: the link is replaced by the archive, not followed.
	if err := d.Put(ctx, link, strings.NewReader("new archive")); err != nil {
		t.Fatal(err)
	}
	if err := d.Put(ctx, dangling, strings.NewReader("new archive")); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(victim); string(data) != "untouched" {
		t.Fatalf("Put wrote through a symbolic link: victim is %q", data)
	}
	if _, err := os.Lstat(filepath.Join(base, "created-through-link")); !os.IsNotExist(err) {
		t.Fatal("Put created a file through a dangling symbolic link")
	}
	for _, name := range []string{link, dangling} {
		fi, err := os.Lstat(filepath.Join(root, name))
		if err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("%s is not a regular file after Put: %v", name, err)
		}
	}

	// Deleted: the link itself.
	if err := os.Remove(filepath.Join(root, link)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(root, link)); err != nil {
		t.Fatal(err)
	}
	if err := d.Delete(ctx, link); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, link)); !os.IsNotExist(err) {
		t.Fatal("the link was not removed")
	}
	if data, _ := os.ReadFile(victim); string(data) != "untouched" {
		t.Fatalf("Delete followed a symbolic link: victim is %q", data)
	}
	if siblings := dirNames(t, base); len(siblings) != 2 {
		t.Fatalf("something appeared beside the share: %v", siblings)
	}
}

func TestOpenDirDestinationValidatesAndNeverFollowsSubpathLinks(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "share")
	elsewhere := filepath.Join(base, "elsewhere")
	for _, p := range []string{root, elsewhere} {
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, subpath := range []string{"/abs", "a//b", "a/", "/a", "..", "a/../b", "./a", "a/.", "a\x00b", strings.Repeat("a/", 300) + "a"} {
		if _, err := OpenDirDestination(root, subpath); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("subpath %q: %v", subpath, err)
		}
	}
	if _, err := OpenDirDestination("relative/root", ""); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("relative root: %v", err)
	}
	if _, err := OpenDirDestination(filepath.Join(base, "missing"), ""); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("missing root: %v", err)
	}
	if got := dirNames(t, root); len(got) != 0 {
		t.Fatalf("a refused subpath created %v", got)
	}

	// A link on the share where the backup directory should be.
	if err := os.Symlink(elsewhere, filepath.Join(root, "backups")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(root, "real", "nested")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, subpath := range []string{"backups", "backups/sub", "real/nested", "real/nested/deeper", "file", "file/sub"} {
		d, err := OpenDirDestination(root, subpath)
		if !errors.Is(err, ErrUnsafePath) {
			t.Errorf("subpath %q through a link or a file: %v", subpath, err)
		}
		if d != nil {
			_ = d.Close()
		}
	}
	if got := dirNames(t, elsewhere); len(got) != 0 {
		t.Fatalf("a directory was created through a link: %v", got)
	}

	// Once open, the destination is the directory it opened, even if the
	// path is swapped for a link afterwards.
	d := openDirDest(t, root, "real/safe")
	if err := os.Rename(filepath.Join(root, "real"), filepath.Join(root, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(root, "real")); err != nil {
		t.Fatal(err)
	}
	name := ArchiveName("m1", day(1))
	if err := d.Put(context.Background(), name, strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "moved", "safe", name)); err != nil {
		t.Fatalf("the archive is not in the directory that was opened: %v", err)
	}
	if got := dirNames(t, elsewhere); len(got) != 0 {
		t.Fatalf("written through a swapped path: %v", got)
	}

	// A closed destination does nothing.
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := d.Put(context.Background(), name, strings.NewReader("x")); err == nil {
		t.Fatal("Put on a closed destination succeeded")
	}
	if _, err := d.List(context.Background()); err == nil {
		t.Fatal("List on a closed destination succeeded")
	}
}
