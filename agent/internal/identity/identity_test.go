package identity

import (
	"os"
	"regexp"
	"testing"
)

func TestInitIsIdempotent(t *testing.T) {
	path := Path(t.TempDir())
	created, err := Init(path, false, nil)
	if err != nil || !created {
		t.Fatalf("first init: %v %v", created, err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("identity must be 0600, got %04o", fi.Mode().Perm())
	}
	first, err := Fingerprint(path)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(first) {
		t.Fatalf("fingerprint format: %q", first)
	}
	created, err = Init(path, false, nil)
	if err != nil || created {
		t.Fatalf("second init must not create: %v %v", created, err)
	}
	second, _ := Fingerprint(path)
	if first != second {
		t.Fatal("the identity changed without --force-regenerate")
	}
	raw, err := Load(path)
	if err != nil || len(raw) != Size {
		t.Fatalf("load: %d %v", len(raw), err)
	}
}

func TestRegenerate(t *testing.T) {
	path := Path(t.TempDir())
	if _, err := Init(path, false, nil); err != nil {
		t.Fatal(err)
	}
	first, _ := Fingerprint(path)
	created, err := Init(path, true, nil)
	if err != nil || !created {
		t.Fatalf("regenerate: %v %v", created, err)
	}
	second, _ := Fingerprint(path)
	if first == second {
		t.Fatal("regenerate must produce a new identity")
	}
}

func TestInitDoesNotOverwriteUnusableIdentity(t *testing.T) {
	path := Path(t.TempDir())
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(path, false, nil); err == nil {
		t.Fatal("a corrupt identity must be reported, not silently replaced")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "corrupt" {
		t.Fatal("the existing file was modified")
	}
}

func TestLoadRefusesLoosePermissions(t *testing.T) {
	path := Path(t.TempDir())
	if _, err := Init(path, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("a world-readable identity must be refused")
	}
}

func TestTwoMachinesGetDifferentIdentities(t *testing.T) {
	a, b := Path(t.TempDir()), Path(t.TempDir())
	if _, err := Init(a, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(b, false, nil); err != nil {
		t.Fatal(err)
	}
	fa, _ := Fingerprint(a)
	fb, _ := Fingerprint(b)
	if fa == fb {
		t.Fatal("identities must be random")
	}
}
