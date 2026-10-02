package fsx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicReplacesAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := WriteFileAtomic(path, []byte("one"), 0o600, nil); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("two"), 0o600, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "two" {
		t.Fatalf("content %q, %v", data, err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestWriteFileAtomicFailureKeepsOldFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := WriteFileAtomic(path, []byte("old"), 0o600, nil); err != nil {
		t.Fatal(err)
	}
	// Renaming a file over a non-empty directory fails: the write must fail
	// cleanly and leave nothing behind.
	target := filepath.Join(dir, "target")
	if err := os.MkdirAll(filepath.Join(target, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(target, []byte("new"), 0o600, nil); err == nil {
		t.Fatal("expected an error")
	}
	if err := WriteFileAtomic(filepath.Join(dir, "missing", "file"), []byte("x"), 0o600, nil); err == nil {
		t.Fatal("expected an error for a missing directory")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "old" {
		t.Fatalf("old file changed: %q", data)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if IsTempName(e.Name()) {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestIsTempName(t *testing.T) {
	if !IsTempName(".credential.json.tmp-123") || IsTempName("credential.json") || IsTempName("00000000000000000001.json") {
		t.Fatal("IsTempName is wrong")
	}
}
