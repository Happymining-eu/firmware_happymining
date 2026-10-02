// Package credential stores the device credential issued at pairing
// (/var/lib/happymining/credential.json, mode 0600, written atomically).
package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
)

// FileName is the credential file name inside the state directory.
const FileName = "credential.json"

// ErrNotPaired is returned by Load when no credential exists.
var ErrNotPaired = errors.New("device is not paired")

// maxFileBytes bounds the credential file that Load is willing to read.
const maxFileBytes = 16 * 1024

// File is the on-disk credential. Token is the only secret field.
type File struct {
	DeviceID     string  `json:"device_id"`
	MachineID    string  `json:"machine_id"`
	CredentialID string  `json:"credential_id"`
	Token        string  `json:"token"`
	ExpiresAt    *string `json:"expires_at"`
	APIURL       string  `json:"api_url"`
	PairedAt     string  `json:"paired_at"`
	RotatedAt    string  `json:"rotated_at,omitempty"`
}

// reToken is the credential format of the protocol:
// hmd_<credential id as 32 hex>.<43-char base64url secret>.
var reToken = regexp.MustCompile(`^hmd_[0-9a-fA-F]{32}\.[A-Za-z0-9_-]{43}$`)

// ValidToken reports whether tok has the protocol's credential format.
func ValidToken(tok string) bool { return reToken.MatchString(tok) }

// Path returns the credential path for a state directory.
func Path(stateDir string) string { return filepath.Join(stateDir, FileName) }

// Validate checks the fields the agent depends on.
func (f *File) Validate() error {
	if f.DeviceID == "" || f.MachineID == "" || f.CredentialID == "" {
		return errors.New("credential is missing device_id, machine_id or credential_id")
	}
	if !ValidToken(f.Token) {
		return errors.New("credential token does not have the expected format")
	}
	return nil
}

// Load reads the credential. It refuses a file that group or others can
// access, so that a permission mistake is noticed instead of ignored.
func Load(path string) (*File, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotPaired
		}
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has permissions %04o; refusing a credential accessible by group or others (expected 0600)",
			path, fi.Mode().Perm())
	}
	if fi.Size() > maxFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxFileBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotPaired
		}
		return nil, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON", path)
	}
	if err := f.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &f, nil
}

// Save writes the credential atomically with mode 0600.
func Save(path string, f *File, owner *fsx.Owner) error {
	if err := f.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return fsx.WriteFileAtomic(path, append(data, '\n'), 0o600, owner)
}

// Delete removes the credential. A missing file is not an error.
func Delete(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return fsx.SyncDir(filepath.Dir(path))
}
