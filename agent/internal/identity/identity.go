// Package identity manages the random install identity of a machine
// (/var/lib/happymining/identity). It is 32 random bytes generated on first
// boot, never derived from hardware serial numbers, and only its SHA-256 is
// ever sent to the API (as machine_fingerprint at enrollment).
package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
)

// FileName is the identity file name inside the state directory.
const FileName = "identity"

// Size is the identity length in bytes.
const Size = 32

// Path returns the identity path for a state directory.
func Path(stateDir string) string { return filepath.Join(stateDir, FileName) }

// randReader is replaced in tests.
var randReader io.Reader = rand.Reader

// Init creates the identity if it does not exist. It never overwrites an
// existing identity unless regenerate is true. It reports whether a new
// identity was written.
func Init(path string, regenerate bool, owner *fsx.Owner) (bool, error) {
	if !regenerate {
		if _, err := Load(path); err == nil {
			return false, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return false, fmt.Errorf("existing identity is unusable (not overwriting it): %w", err)
		}
	}
	raw := make([]byte, Size)
	if _, err := io.ReadFull(randReader, raw); err != nil {
		return false, fmt.Errorf("read random bytes: %w", err)
	}
	data := []byte(hex.EncodeToString(raw) + "\n")
	if regenerate {
		if err := fsx.WriteFileAtomic(path, data, 0o600, owner); err != nil {
			return false, err
		}
		return true, nil
	}
	// Write a complete temporary file first, then hard-link it into place:
	// link(2) fails if the target exists, so an existing identity is never
	// replaced and a crash never leaves a partial identity behind.
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+FileName+".tmp-*")
	if err != nil {
		return false, fmt.Errorf("create identity: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	fail := func(err error) (bool, error) {
		_ = f.Close()
		return false, err
	}
	if err := f.Chmod(0o600); err != nil {
		return fail(fmt.Errorf("chmod identity: %w", err))
	}
	if owner != nil {
		if err := f.Chown(owner.UID, owner.GID); err != nil {
			return fail(fmt.Errorf("chown identity: %w", err))
		}
	}
	if _, err := f.Write(data); err != nil {
		return fail(fmt.Errorf("write identity: %w", err))
	}
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("fsync identity: %w", err))
	}
	if err := f.Close(); err != nil {
		return false, fmt.Errorf("close identity: %w", err)
	}
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("install identity: %w", err)
	}
	if err := fsx.SyncDir(dir); err != nil {
		return false, err
	}
	return true, nil
}

// Load returns the 32 identity bytes.
func Load(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has permissions %04o; refusing an identity readable by group or others", path, fi.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) != Size {
		return nil, fmt.Errorf("%s does not contain a %d-byte hex identity", path, Size)
	}
	return raw, nil
}

// Fingerprint returns "sha256:<64 hex>" of the identity at path.
func Fingerprint(path string) (string, error) {
	raw, err := Load(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
