package localui

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
)

// The unlock file is how the local web UI learns that somebody with console
// or SSH access to this machine allows an action (pairing) from a browser on
// the LAN. `happyminingctl ui unlock` writes it with a short random code,
// prints the code, and the browser has a few minutes and a few attempts to
// type it. The file never holds the code itself, only its hash, and it is
// deleted after one successful unlock or too many failures. Without it the UI
// is read-only: nobody on the network can pair this machine to another
// organisation just because the page is reachable.
const (
	UnlockFileName    = "ui-unlock.json"
	UnlockCodeDigits  = 6
	DefaultUnlockTTL  = 10 * time.Minute
	MaxUnlockTTL      = time.Hour
	MaxUnlockAttempts = 5
)

// ErrNoUnlock is returned when no valid unlock file exists.
var ErrNoUnlock = errors.New("the UI is locked: run `sudo happyminingctl ui unlock` on this machine")

// UnlockFile is the on-disk record.
type UnlockFile struct {
	CodeHash  string `json:"code_hash"`
	ExpiresAt string `json:"expires_at"`
}

// UnlockPath returns the unlock file path for a state directory.
func UnlockPath(stateDir string) string { return filepath.Join(stateDir, UnlockFileName) }

// NewUnlockCode returns a fresh random code of UnlockCodeDigits decimal digits.
func NewUnlockCode() (string, error) {
	limit := big.NewInt(1)
	for i := 0; i < UnlockCodeDigits; i++ {
		limit.Mul(limit, big.NewInt(10))
	}
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", UnlockCodeDigits, n), nil
}

// HashCode is the stored form of a code.
func HashCode(code string) string {
	sum := sha256.Sum256([]byte("happymining-ui-unlock\x00" + code))
	return hex.EncodeToString(sum[:])
}

// WriteUnlock stores the hash of code with an expiry. The file is created
// 0600 and, when owner is set (root writing into the agent's directory),
// handed to that account so the UI service can read it.
func WriteUnlock(stateDir, code string, expires time.Time, owner *fsx.Owner) error {
	data, err := json.Marshal(UnlockFile{CodeHash: HashCode(code), ExpiresAt: expires.UTC().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	return fsx.WriteFileAtomic(UnlockPath(stateDir), append(data, '\n'), 0o600, owner)
}

// ReadUnlock loads the unlock file. An expired file is deleted and reported
// as ErrNoUnlock.
func ReadUnlock(stateDir string, now time.Time) (*UnlockFile, error) {
	data, err := os.ReadFile(UnlockPath(stateDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoUnlock
		}
		return nil, err
	}
	var f UnlockFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("unlock file: %w", err)
	}
	expires, err := time.Parse(time.RFC3339, f.ExpiresAt)
	if err != nil || len(f.CodeHash) != sha256.Size*2 {
		return nil, errors.New("unlock file: malformed")
	}
	if !now.Before(expires) {
		_ = DeleteUnlock(stateDir)
		return nil, ErrNoUnlock
	}
	return &f, nil
}

// DeleteUnlock removes the unlock file; a missing file is not an error.
func DeleteUnlock(stateDir string) error {
	err := os.Remove(UnlockPath(stateDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Matches compares a typed code with the stored hash in constant time.
func (f *UnlockFile) Matches(code string) bool {
	return subtle.ConstantTimeCompare([]byte(HashCode(code)), []byte(f.CodeHash)) == 1
}
