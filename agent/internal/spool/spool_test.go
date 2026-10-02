package spool

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func sample(seq uint64, size int) []byte {
	pad := bytes.Repeat([]byte("x"), size)
	return []byte(fmt.Sprintf(`{"seq":%d,"pad":"%s"}`, seq, pad))
}

func seqs(entries []Entry) []uint64 {
	var out []uint64
	for _, e := range entries {
		out = append(out, e.Seq)
	}
	return out
}

func TestOrderingAndDelete(t *testing.T) {
	s, err := Open(t.TempDir(), 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	for seq := uint64(1); seq <= 250; seq++ {
		if _, err := s.Put(seq, sample(seq, 10)); err != nil {
			t.Fatal(err)
		}
	}
	batch := s.Peek(100, 1<<20)
	if len(batch) != 100 || batch[0].Seq != 1 || batch[99].Seq != 100 {
		t.Fatalf("first batch must be the 100 oldest, got %v..%v (%d)", batch[0].Seq, batch[len(batch)-1].Seq, len(batch))
	}
	for i := 1; i < len(batch); i++ {
		if batch[i].Seq <= batch[i-1].Seq {
			t.Fatal("batch is not oldest first")
		}
	}
	// Peeking again without deleting returns the same samples (resend safety).
	again := s.Peek(100, 1<<20)
	if fmt.Sprint(seqs(again)) != fmt.Sprint(seqs(batch)) || !bytes.Equal(again[0].Data, batch[0].Data) {
		t.Fatal("an unacknowledged batch must be returned unchanged")
	}
	if err := s.Delete(seqs(batch)); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 150 {
		t.Fatalf("Len = %d", s.Len())
	}
	next := s.Peek(100, 1<<20)
	if next[0].Seq != 101 {
		t.Fatalf("after delete the oldest must be 101, got %d", next[0].Seq)
	}
}

func TestPeekRespectsByteBudget(t *testing.T) {
	s, _ := Open(t.TempDir(), 4*1024*1024)
	for seq := uint64(1); seq <= 10; seq++ {
		if _, err := s.Put(seq, sample(seq, 1000)); err != nil {
			t.Fatal(err)
		}
	}
	batch := s.Peek(100, 3500)
	if len(batch) != 3 {
		t.Fatalf("want 3 samples in 3500 bytes, got %d", len(batch))
	}
	// A budget smaller than one sample still returns one (never zero).
	if one := s.Peek(100, 10); len(one) != 1 {
		t.Fatalf("want 1, got %d", len(one))
	}
}

func TestQuotaEvictsOldestFirst(t *testing.T) {
	dir := t.TempDir()
	const quota = MaxSampleBytes // fits 6 samples of ~10 KiB
	s, err := Open(dir, quota)
	if err != nil {
		t.Fatal(err)
	}
	evictedTotal := 0
	for seq := uint64(1); seq <= 20; seq++ {
		n, err := s.Put(seq, sample(seq, 10*1024))
		if err != nil {
			t.Fatal(err)
		}
		evictedTotal += n
		if s.Size() > quota {
			t.Fatalf("spool size %d above quota %d", s.Size(), quota)
		}
	}
	if evictedTotal == 0 || s.Dropped() != uint64(evictedTotal) {
		t.Fatalf("drop counter: evicted %d, Dropped() %d", evictedTotal, s.Dropped())
	}
	left := seqs(s.Peek(100, 1<<30))
	if left[len(left)-1] != 20 {
		t.Fatalf("the newest sample must survive, got %v", left)
	}
	if left[0] != uint64(20-len(left)+1) {
		t.Fatalf("survivors must be the newest contiguous samples, got %v", left)
	}
	files, _ := os.ReadDir(dir)
	if len(files) != len(left) {
		t.Fatalf("%d files on disk for %d samples", len(files), len(left))
	}
}

func TestReopenKeepsSamplesAndRemovesTempFiles(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 1024*1024)
	for seq := uint64(5); seq <= 9; seq++ {
		if _, err := s.Put(seq, sample(seq, 10)); err != nil {
			t.Fatal(err)
		}
	}
	// A crash between write and rename leaves a temporary file.
	if err := os.WriteFile(filepath.Join(dir, ".00000000000000000010.json.tmp-123"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Len() != 5 || s2.HighestSeq() != 9 || s2.Size() != s.Size() {
		t.Fatalf("reopen: len %d highest %d size %d", s2.Len(), s2.HighestSeq(), s2.Size())
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 5 {
		t.Fatalf("temporary file not removed: %d files", len(files))
	}
}

func TestPutRejectsBadInput(t *testing.T) {
	s, _ := Open(t.TempDir(), 1024*1024)
	if _, err := s.Put(1, nil); err == nil {
		t.Fatal("empty sample accepted")
	}
	if _, err := s.Put(1, bytes.Repeat([]byte("x"), MaxSampleBytes+1)); err == nil {
		t.Fatal("oversized sample accepted")
	}
	if _, err := s.Put(5, sample(5, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(5, sample(5, 1)); err == nil {
		t.Fatal("a repeated sequence number must be refused")
	}
	if _, err := s.Put(4, sample(4, 1)); err == nil {
		t.Fatal("a lower sequence number must be refused")
	}
	if _, err := Open(t.TempDir(), 10); err == nil {
		t.Fatal("a quota below one sample must be refused")
	}
}

func TestCorruptFilesAreDroppedNotSent(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 1024*1024)
	for seq := uint64(1); seq <= 3; seq++ {
		if _, err := s.Put(seq, sample(seq, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, name(2)), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := seqs(s.Peek(100, 1<<20))
	if fmt.Sprint(got) != "[1 3]" || s.Dropped() != 1 {
		t.Fatalf("got %v dropped %d", got, s.Dropped())
	}
}

func TestPurgeAndDeviceMarker(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 1024*1024)
	if s.Device() != "" {
		t.Fatal("a new spool has no owner")
	}
	if err := s.SetDevice("device-a"); err != nil {
		t.Fatal(err)
	}
	for seq := uint64(1); seq <= 3; seq++ {
		_, _ = s.Put(seq, sample(seq, 1))
	}
	s2, _ := Open(dir, 1024*1024)
	if s2.Device() != "device-a" || s2.Len() != 3 {
		t.Fatalf("marker or samples lost: %q %d", s2.Device(), s2.Len())
	}
	if err := s2.Purge(); err != nil || s2.Len() != 0 || s2.Size() != 0 || s2.Dropped() != 3 {
		t.Fatalf("purge: %v len %d size %d dropped %d", err, s2.Len(), s2.Size(), s2.Dropped())
	}
	n, size, err := Stat(dir)
	if err != nil || n != 0 || size != 0 {
		t.Fatalf("Stat after purge: %d %d %v", n, size, err)
	}
}

func TestSequencePersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), SequenceFileName)
	s, err := OpenSequence(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	var last uint64
	for i := 0; i < 5; i++ {
		n, err := s.Next()
		if err != nil {
			t.Fatal(err)
		}
		if n != last+1 {
			t.Fatalf("not strictly increasing by one: %d after %d", n, last)
		}
		last = n
		// Write-ahead: the number is on disk before it is used.
		data, _ := os.ReadFile(path)
		if string(data) != fmt.Sprintf("%d\n", n) {
			t.Fatalf("counter file holds %q after issuing %d", data, n)
		}
	}
	// "Restart": a new process opens the same file.
	s2, err := OpenSequence(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := s2.Next()
	if n != 6 {
		t.Fatalf("after restart want 6, got %d", n)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o", fi.Mode().Perm())
	}
}

func TestSequenceNeverGoesBelowTheSpool(t *testing.T) {
	path := filepath.Join(t.TempDir(), SequenceFileName)
	// Counter file lost, but the spool still holds sample 41.
	s, err := OpenSequence(path, 41)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Next(); n != 42 {
		t.Fatalf("want 42, got %d", n)
	}
	// Corrupt counter: reported, and the floor is used.
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err = OpenSequence(path, 100)
	if err == nil {
		t.Fatal("a corrupt counter must be reported")
	}
	if n, _ := s.Next(); n != 101 {
		t.Fatalf("want 101, got %d", n)
	}
}

func TestSequenceAdvanceTo(t *testing.T) {
	path := filepath.Join(t.TempDir(), SequenceFileName)
	s, _ := OpenSequence(path, 0)
	if err := s.AdvanceTo(1000); err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceTo(10); err != nil || s.Last() != 1000 {
		t.Fatalf("AdvanceTo must never go backwards: %d %v", s.Last(), err)
	}
	if n, _ := s.Next(); n != 1001 {
		t.Fatalf("want 1001, got %d", n)
	}
	if err := s.AdvanceTo(^uint64(0)); err == nil {
		t.Fatal("an absurd server value must be refused")
	}
	s2, _ := OpenSequence(path, 0)
	if s2.Last() != 1001 {
		t.Fatalf("AdvanceTo not persisted: %d", s2.Last())
	}
}
