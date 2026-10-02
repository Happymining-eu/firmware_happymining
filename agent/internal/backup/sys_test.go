package backup

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The relative system-call wrappers refuse any name that is not a single
// component, whatever the caller checked before. An absolute name would make
// the kernel ignore the directory descriptor: unlinkat(fd, "/etc/passwd") run
// as root deletes the system's account file. This test names a file of its
// own instead, and fails if any wrapper lets such a name through.
func TestRelativeSyscallsRefuseNamesOutsideTheDirectory(t *testing.T) {
	base := t.TempDir()
	victim := filepath.Join(base, "victim")
	writeFile(t, victim, []byte("untouched"), 0o644, testCreated)
	dir := filepath.Join(base, "d")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "x"), []byte("x"), 0o644, testCreated)
	fd, err := openDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFd(fd)

	outside := []string{victim, "../victim", "sub/../../victim", "", "..", "a\x00b"}
	for _, name := range outside {
		if err := unlinkat(fd, name); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("unlinkat %q: %v", name, err)
		}
		if err := renameat(fd, "x", name); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("renameat x -> %q: %v", name, err)
		}
		if err := renameat(fd, name, "y"); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("renameat %q -> y: %v", name, err)
		}
		if got, err := openat(fd, name, syscall.O_WRONLY|syscall.O_TRUNC|openSafe, 0); !errors.Is(err, ErrUnsafePath) {
			if got >= 0 {
				closeFd(got)
			}
			t.Errorf("openat %q: %v", name, err)
		}
	}
	// Names that would create something next to the directory.
	for _, name := range []string{filepath.Join(base, "made"), "../made", "sub/../../made", "", ".."} {
		if err := mkdirat(fd, name, 0o700); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("mkdirat %q: %v", name, err)
		}
		if err := symlinkat("target", fd, name); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("symlinkat %q: %v", name, err)
		}
	}
	if data, err := os.ReadFile(victim); err != nil || string(data) != "untouched" {
		t.Fatalf("the file outside the directory was changed: %q, %v", data, err)
	}
	if names := dirNames(t, base); len(names) != 2 {
		t.Fatalf("something was created next to the directory: %v", names)
	}
	if names := dirNames(t, dir); len(names) != 1 || names[0] != "x" {
		t.Fatalf("the directory holds %v", names)
	}

	// One component, and the directory itself, still work.
	if err := renameat(fd, "x", "y"); err != nil {
		t.Fatalf("rename inside the directory: %v", err)
	}
	if err := unlinkat(fd, "y"); err != nil {
		t.Fatalf("unlink inside the directory: %v", err)
	}
	dot, err := openat(fd, ".", syscall.O_RDONLY|syscall.O_DIRECTORY|openSafe, 0)
	if err != nil {
		t.Fatalf("open the directory itself: %v", err)
	}
	closeFd(dot)
}
