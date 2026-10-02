package credential

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
)

const testToken = "hmd_0123456789abcdef0123456789abcdef.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func sample() *File {
	return &File{DeviceID: "d", MachineID: "m", CredentialID: "c", Token: testToken, APIURL: "https://api.example.test"}
}

func TestValidToken(t *testing.T) {
	if !ValidToken(testToken) {
		t.Fatal("valid token rejected")
	}
	for _, bad := range []string{
		"", "hmd_", "hmd_0123.abc", testToken + "A", strings.Replace(testToken, "hmd_", "hmx_", 1),
		testToken + "\n", "Bearer " + testToken, strings.Replace(testToken, ".", "", 1),
	} {
		if ValidToken(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestSaveLoadPermissions(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)
	if _, err := Load(path); !errors.Is(err, ErrNotPaired) {
		t.Fatalf("want ErrNotPaired, got %v", err)
	}
	if err := Save(path, sample(), nil); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("credential must be 0600: %v %v", fi.Mode().Perm(), err)
	}
	got, err := Load(path)
	if err != nil || got.Token != testToken || got.DeviceID != "d" {
		t.Fatalf("load: %+v %v", got, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left: %v", entries)
	}
}

func TestLoadRefusesLoosePermissions(t *testing.T) {
	path := Path(t.TempDir())
	if err := Save(path, sample(), nil); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		if err == nil {
			t.Fatalf("mode %04o must be refused", mode)
		}
		if strings.Contains(err.Error(), testToken) {
			t.Fatal("error leaks the token")
		}
	}
}

func TestSaveIsAtomicAndKeepsOldOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)
	if err := Save(path, sample(), nil); err != nil {
		t.Fatal(err)
	}
	bad := sample()
	bad.Token = "not-a-token"
	if err := Save(path, bad, nil); err == nil {
		t.Fatal("an invalid credential must not be saved")
	}
	// A write that cannot complete (unusable owner for a non-root caller, or
	// a vanished directory) must leave the old credential in place.
	gone := filepath.Join(dir, "gone", FileName)
	if err := Save(gone, sample(), nil); err == nil {
		t.Fatal("expected an error")
	}
	got, err := Load(path)
	if err != nil || got.Token != testToken {
		t.Fatalf("old credential lost: %v", err)
	}
	for _, e := range mustReadDir(t, dir) {
		if fsx.IsTempName(e) {
			t.Fatalf("temporary file left behind: %s", e)
		}
	}
}

func TestLoadRejectsGarbage(t *testing.T) {
	path := Path(t.TempDir())
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("garbage must be an error")
	}
	if err := os.WriteFile(path, []byte(`{"device_id":"d","machine_id":"m","credential_id":"c","token":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("a bad token must be an error")
	}
}

func TestDelete(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)
	if err := Save(path, sample(), nil); err != nil {
		t.Fatal(err)
	}
	if err := Delete(path); err != nil {
		t.Fatal(err)
	}
	if err := Delete(path); err != nil {
		t.Fatalf("deleting twice must not fail: %v", err)
	}
	if _, err := Load(path); !errors.Is(err, ErrNotPaired) {
		t.Fatalf("want ErrNotPaired, got %v", err)
	}
}

func mustReadDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
