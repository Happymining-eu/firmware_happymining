package backup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func runOptions(t *testing.T, dest Destination, key Key, items ...Item) RunOptions {
	t.Helper()
	return RunOptions{Key: key, Destination: dest, MachineID: testMachine, AgentVersion: "0.2.0", Items: items, Now: testCreated}
}

// bigFile is a file of random data larger than two stream chunks, so that an
// archive holding it has several chunks and, with the test part size, many S3
// parts.
func bigFile(t *testing.T) (path string, size int64) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "model.bin")
	writeFile(t, path, randomBytes(t, 2*ChunkSize+ChunkSize/2), 0o644, testCreated)
	return path, 2*ChunkSize + ChunkSize/2
}

// deepTree is a directory that WriteArchive refuses after it has already
// produced a megabyte of output: a big file, then directories nested too deep.
func deepTree(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "volume")
	writeFile(t, filepath.Join(root, "a-big"), randomBytes(t, 1<<20), 0o644, testCreated)
	if err := os.MkdirAll(filepath.Join(root, "z"+strings.Repeat("/d", maxDepth+2)), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestRunAndRestoreThroughEveryDestination(t *testing.T) {
	src, counts := sourceTree(t)
	single := filepath.Join(t.TempDir(), "applied.json")
	writeFile(t, single, []byte(`{"schema":1}`), 0o600, testCreated)
	big, bigSize := bigFile(t)
	items := []Item{{Name: "volumes/qdrant/storage", Path: src}, {Name: "document", Path: single}, {Name: "models/blob", Path: big}}
	key := mustNewKey(t)
	wantName := "hm-backup-" + testMachine + "-20261002T030000Z.hmbk"

	fake := newFakeS3(t)
	destinations := map[string]Destination{
		"memory":    newMemDest(),
		"directory": openDirDest(t, t.TempDir(), "happymining"),
		"s3":        newTestS3(t, fake, "site/backups"),
	}
	for name, dest := range destinations {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			res, err := Run(ctx, runOptions(t, dest, key, items...))
			if err != nil {
				t.Fatal(err)
			}
			if res.Name != wantName || res.KeyID != KeyID(key) {
				t.Fatalf("result %+v", res)
			}
			if res.Stats.Files != counts.files+2 || res.Stats.Symlinks != counts.symlinks || res.Stats.Skipped != counts.special ||
				res.Stats.Bytes != counts.bytes+bigSize+int64(len(`{"schema":1}`)) {
				t.Fatalf("stats %+v", res.Stats)
			}
			entries, err := dest.List(ctx)
			if err != nil || len(entries) != 1 || entries[0].Name != wantName || entries[0].Size != res.Size {
				t.Fatalf("list %+v (result size %d), %v", entries, res.Size, err)
			}
			// Several megabytes of random data: several chunks and, for S3,
			// a multipart upload.
			if res.Size < 2*ChunkSize {
				t.Fatalf("archive of %d bytes", res.Size)
			}

			// What is stored is an HMBK1 archive of this key and says nothing
			// in clear.
			rc, err := dest.Get(ctx, wantName)
			if err != nil {
				t.Fatal(err)
			}
			stored, err := io.ReadAll(rc)
			_ = rc.Close()
			if err != nil || int64(len(stored)) != res.Size {
				t.Fatalf("stored %d bytes, %v", len(stored), err)
			}
			h, err := ReadHeader(bytes.NewReader(stored))
			if err != nil || h.KeyID() != KeyID(key) || h.ChunkSize != ChunkSize {
				t.Fatalf("header %+v, %v", h, err)
			}
			for _, clear := range []string{"manifest.json", "hello.txt", testMachine, `{"schema":1}`, "volumes/qdrant"} {
				if bytes.Contains(stored, []byte(clear)) {
					t.Fatalf("%q is readable in the stored archive", clear)
				}
			}

			// Restore from the destination.
			restored := filepath.Join(t.TempDir(), "restore")
			out, err := Restore(ctx, RestoreOptions{Key: key, Destination: dest, Name: wantName, DestDir: restored})
			if err != nil {
				t.Fatal(err)
			}
			if out.Manifest.MachineID != testMachine || !out.Manifest.CreatedAt.Equal(testCreated) || len(out.Manifest.Items) != 3 ||
				out.Files != res.Stats.Files || out.Bytes != res.Stats.Bytes {
				t.Fatalf("restore result %+v", out)
			}
			compareTrees(t, src, filepath.Join(restored, "volumes/qdrant/storage"))
			if data, _ := os.ReadFile(filepath.Join(restored, "document/applied.json")); string(data) != `{"schema":1}` {
				t.Fatalf("file item: %q", data)
			}
			wantBig, _ := os.ReadFile(big)
			if data, _ := os.ReadFile(filepath.Join(restored, "models/blob/model.bin")); !bytes.Equal(data, wantBig) {
				t.Fatalf("big file item: %d bytes", len(data))
			}

			// Restore from a stream (a local file given to the restore
			// command).
			fromStream := filepath.Join(t.TempDir(), "restore")
			if _, err := Restore(ctx, RestoreOptions{Key: key, Source: bytes.NewReader(stored), DestDir: fromStream}); err != nil {
				t.Fatal(err)
			}
			compareTrees(t, src, filepath.Join(fromStream, "volumes/qdrant/storage"))
		})
	}
	if fake.count("CreateMultipartUpload") != 1 || fake.count("CompleteMultipartUpload") != 1 || fake.count("PutObject") != 0 {
		t.Fatalf("the S3 run was not one multipart upload: %d parts", fake.count("UploadPart#"))
	}
	if fake.numUploads() != 0 {
		t.Fatal("an upload is left open")
	}
}

func TestRestoreRefusesTheWrongKeyBeforeTouchingAnything(t *testing.T) {
	src, _ := sourceTree(t)
	key, other := mustNewKey(t), mustNewKey(t)
	dest := newMemDest()
	res, err := Run(context.Background(), runOptions(t, dest, key, Item{Name: "data", Path: src}))
	if err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restore")
	_, err = Restore(context.Background(), RestoreOptions{Key: other, Destination: dest, Name: res.Name, DestDir: restored})
	if !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong key: %v", err)
	}
	var mismatch *KeyMismatchError
	if !errors.As(err, &mismatch) || mismatch.ArchiveKeyID != res.KeyID {
		t.Fatalf("mismatch %+v", mismatch)
	}
	if _, err := os.Lstat(restored); !os.IsNotExist(err) {
		t.Fatal("the restore directory was created for a wrong key")
	}
	if _, err := Restore(context.Background(), RestoreOptions{Key: Key{}, Destination: dest, Name: res.Name, DestDir: restored}); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("zero key: %v", err)
	}
}

func TestRestoreRefusesDamagedArchives(t *testing.T) {
	src, _ := sourceTree(t)
	big, _ := bigFile(t)
	key := mustNewKey(t)
	dest := newMemDest()
	res, err := Run(context.Background(), runOptions(t, dest, key, Item{Name: "data", Path: src}, Item{Name: "big", Path: big}))
	if err != nil {
		t.Fatal(err)
	}
	stored := dest.objects[res.Name]
	header, chunks := splitArchive(t, stored)
	if len(chunks) < 3 {
		t.Fatalf("%d chunks", len(chunks))
	}
	last := len(chunks) - 1
	restore := func(archive []byte) error {
		_, err := Restore(context.Background(), RestoreOptions{Key: key, Source: bytes.NewReader(archive), DestDir: filepath.Join(t.TempDir(), "r")})
		return err
	}
	if err := restore(stored); err != nil {
		t.Fatalf("the untouched archive: %v", err)
	}
	for name, c := range map[string]struct {
		archive []byte
		want    error
	}{
		"final chunk missing":       {joinArchive(header, chunks[:last]...), ErrTruncated},
		"cut in the middle":         {stored[:len(stored)/2], ErrTruncated},
		"last byte missing":         {stored[:len(stored)-1], ErrTruncated},
		"header only":               {stored[:HeaderSize], ErrTruncated},
		"data after the end":        {append(append([]byte(nil), stored...), chunks[0]...), ErrTrailingData},
		"one byte after the end":    {append(append([]byte(nil), stored...), 0), ErrTrailingData},
		"first chunk altered":       {joinArchive(header, append([][]byte{flip(chunks[0], 50)}, chunks[1:]...)...), ErrKeyOrHeader},
		"final chunk altered":       {joinArchive(header, append(append([][]byte(nil), chunks[:last]...), flip(chunks[last], 9))...), ErrCorrupt},
		"chunks swapped":            {joinArchive(header, append([][]byte{chunks[1], chunks[0]}, chunks[2:]...)...), ErrKeyOrHeader},
		"not an archive":            {[]byte("definitely not an archive, but longer than a header"), ErrBadHeader},
		"empty":                     {nil, ErrBadHeader},
		"salt altered":              {joinArchive(flip(header, 15), chunks...), ErrKeyOrHeader},
		"encrypted, but not a tar":  {encryptWith(t, key, ChunkSize, []byte("plain text, not gzip")), ErrBadArchive},
		"encrypted, but empty":      {encryptWith(t, key, ChunkSize, nil), ErrBadArchive},
		"over-long chunk announced": {append(append([]byte(nil), header...), 0xff, 0xff, 0xff, 0xff), ErrChunkLength},
	} {
		if err := restore(c.archive); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}

	// From a destination: a missing archive, a bad name, nothing to restore.
	for name, opts := range map[string]RestoreOptions{
		"missing":        {Key: key, Destination: dest, Name: ArchiveName(testMachine, testCreated.Add(time.Hour)), DestDir: t.TempDir()},
		"bad name":       {Key: key, Destination: dest, Name: "../x", DestDir: t.TempDir()},
		"no source":      {Key: key, DestDir: t.TempDir()},
		"no destination": {Key: key, Source: bytes.NewReader(stored)},
	} {
		_, err := Restore(context.Background(), opts)
		want := map[string]error{"missing": ErrNotFound, "bad name": ErrInvalidName, "no source": ErrInvalidConfig, "no destination": ErrInvalidConfig}[name]
		if !errors.Is(err, want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRunStoresNothingWhenTheSourceFails(t *testing.T) {
	key := mustNewKey(t)
	bad := deepTree(t)
	good, _ := sourceTree(t)
	dirRoot := t.TempDir()
	fake := newFakeS3(t)
	mem := newMemDest()
	destinations := map[string]Destination{
		"memory":    mem,
		"directory": openDirDest(t, dirRoot, ""),
		"s3":        newTestS3(t, fake, ""),
	}
	for name, dest := range destinations {
		res, err := Run(context.Background(), runOptions(t, dest, key, Item{Name: "good", Path: good}, Item{Name: "bad", Path: bad}))
		if !errors.Is(err, ErrInvalidItem) || res.Name != "" {
			t.Fatalf("%s: result %+v, error %v", name, res, err)
		}
		// The cause is the source, not the upload that was interrupted.
		var ee *EntryError
		if !errors.As(err, &ee) || ee.Item != "bad" {
			t.Fatalf("%s: %v", name, err)
		}
		entries, lerr := dest.List(context.Background())
		if lerr != nil || len(entries) != 0 {
			t.Fatalf("%s: a failed run left %+v, %v", name, entries, lerr)
		}
	}
	if len(mem.objects) != 0 {
		t.Fatal("memory destination holds an object")
	}
	if got := dirNames(t, dirRoot); len(got) != 0 {
		t.Fatalf("the directory holds %v", got)
	}
	// S3: the megabyte already sent was a multipart upload, and it was
	// aborted.
	if fake.count("CreateMultipartUpload") != 1 || fake.count("AbortMultipartUpload") != 1 || fake.count("CompleteMultipartUpload") != 0 ||
		fake.numUploads() != 0 || fake.numObjects() != 0 {
		t.Fatalf("s3 operations: create %d, abort %d, complete %d, uploads %d, objects %d", fake.count("CreateMultipartUpload"),
			fake.count("AbortMultipartUpload"), fake.count("CompleteMultipartUpload"), fake.numUploads(), fake.numObjects())
	}

	// A source that does not exist fails before anything is sent.
	_, err := Run(context.Background(), runOptions(t, mem, key, Item{Name: "gone", Path: filepath.Join(dirRoot, "missing")}))
	if err == nil || len(mem.objects) != 0 {
		t.Fatalf("missing source: %v", err)
	}
}

func TestRunReportsDestinationFailures(t *testing.T) {
	key := mustNewKey(t)
	src, _ := sourceTree(t)
	item := Item{Name: "data", Path: src}
	before := runtime.NumGoroutine()

	boom := errors.New("share is read-only")
	dest := newMemDest()
	dest.putErr = boom
	if _, err := Run(context.Background(), runOptions(t, dest, key, item)); !errors.Is(err, boom) {
		t.Fatalf("failing Put: %v", err)
	}

	// A destination that stops reading early and fails: the producing side
	// must not stay blocked.
	early := &earlyDest{err: boom}
	if _, err := Run(context.Background(), runOptions(t, early, key, item)); !errors.Is(err, boom) {
		t.Fatalf("early failure: %v", err)
	}
	// A destination that reports success without having read the archive is
	// not believed.
	short := newMemDest()
	short.shortPut = true
	res, err := Run(context.Background(), runOptions(t, short, key, item))
	if err == nil || res.Name != "" || !strings.Contains(err.Error(), "did not store the whole archive") {
		t.Fatalf("short Put: %+v, %v", res, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, runOptions(t, newMemDest(), key, item)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}

	// No goroutine is left behind by the failed runs.
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		t.Fatalf("%d goroutines before, %d after", before, n)
	}
}

type earlyDest struct {
	memDest
	err error
}

func (e *earlyDest) Put(_ context.Context, _ string, r io.Reader) error {
	_, _ = io.CopyN(io.Discard, r, 100)
	return e.err
}

func TestRunValidatesItsOptions(t *testing.T) {
	key := mustNewKey(t)
	src, _ := sourceTree(t)
	item := Item{Name: "data", Path: src}
	dest := newMemDest()
	for name, change := range map[string]func(o *RunOptions){
		"no destination":  func(o *RunOptions) { o.Destination = nil },
		"bad machine id":  func(o *RunOptions) { o.MachineID = "../../x" },
		"no machine id":   func(o *RunOptions) { o.MachineID = "" },
		"bad version":     func(o *RunOptions) { o.AgentVersion = "0.2.0 (dirty)" },
		"year 10000":      func(o *RunOptions) { o.Now = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		"bad item":        func(o *RunOptions) { o.Items = []Item{{Name: "../x", Path: src}} },
		"relative source": func(o *RunOptions) { o.Items = []Item{{Name: "x", Path: "relative"}} },
	} {
		opts := runOptions(t, dest, key, item)
		change(&opts)
		_, err := Run(context.Background(), opts)
		if !errors.Is(err, ErrInvalidConfig) && !errors.Is(err, ErrInvalidItem) {
			t.Errorf("%s: %v", name, err)
		}
	}
	opts := runOptions(t, dest, Key{}, item)
	if _, err := Run(context.Background(), opts); !errors.Is(err, ErrZeroKey) {
		t.Errorf("zero key: %v", err)
	}
	if len(dest.objects) != 0 {
		t.Fatalf("something was stored: %v", dest.names())
	}

	// Without a time, the run is named after now.
	opts = runOptions(t, dest, key, item)
	opts.Now = time.Time{}
	start := time.Now().Add(-time.Second)
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	_, at, err := ParseArchiveName(res.Name)
	if err != nil || at.Before(start.Truncate(time.Second)) || at.After(time.Now().Add(time.Second)) {
		t.Fatalf("name %q: %v, %v", res.Name, at, err)
	}
}

// The whole cycle a schedule performs: run, then prune.
func TestRunThenPrune(t *testing.T) {
	key := mustNewKey(t)
	src := filepath.Join(t.TempDir(), "volume")
	writeFile(t, filepath.Join(src, "f"), []byte("content"), 0o644, testCreated)
	root := t.TempDir()
	dest := openDirDest(t, root, "")
	if err := os.WriteFile(filepath.Join(root, "unrelated.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var names []string
	for d := 0; d < 5; d++ {
		opts := runOptions(t, dest, key, Item{Name: "data", Path: src})
		opts.Now = testCreated.AddDate(0, 0, d)
		res, err := Run(context.Background(), opts)
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, res.Name)
		deleted, err := Prune(context.Background(), dest, testMachine, 3)
		if err != nil {
			t.Fatal(err)
		}
		if wantDeleted := max(0, d+1-3); len(deleted) != min(wantDeleted, 1) {
			t.Fatalf("run %d: deleted %v", d, deleted)
		}
	}
	got := dirNames(t, root)
	want := append([]string{}, names[2:]...)
	want = append(want, "unrelated.txt")
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("left %v, want %v", got, want)
	}
	// The newest restores.
	if _, err := Restore(context.Background(), RestoreOptions{Key: key, Destination: dest, Name: names[4], DestDir: filepath.Join(t.TempDir(), "r")}); err != nil {
		t.Fatal(err)
	}
}
