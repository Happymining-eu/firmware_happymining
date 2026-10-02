package backup

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"
)

// KeySize is the size of a backup key in bytes.
const KeySize = 32

// Key is a backup key: 32 random bytes generated on the machine. It is the
// only thing that opens the machine's archives.
//
// A Key prints as "backup.Key(redacted)" with every fmt verb and refuses to be
// marshalled, so that it cannot reach a log, a heartbeat or an operation
// result by accident. The only textual form is FormatRecoveryKey.
type Key [KeySize]byte

const redactedKey = "backup.Key(redacted)"

// Format implements fmt.Formatter: no verb prints the key.
func (Key) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedKey) }

// String implements fmt.Stringer.
func (Key) String() string { return redactedKey }

// MarshalText refuses: a key is never serialised (this also stops
// encoding/json).
func (Key) MarshalText() ([]byte, error) {
	return nil, errors.New("backup: a key is never serialised")
}

// IsZero reports whether k is the all-zero key, which is what an uninitialised
// Key looks like.
func (k Key) IsZero() bool {
	var zero Key
	return subtle.ConstantTimeCompare(k[:], zero[:]) == 1
}

// NewKey returns a new random key.
func NewKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, fmt.Errorf("backup: generate key: %w", err)
	}
	return k, nil
}

// KeyID returns the key id the machine reports: the first 8 hexadecimal
// characters of SHA-256 of the key. It identifies a key without revealing it.
func KeyID(key Key) string {
	sum := sha256.Sum256(key[:])
	return hex.EncodeToString(sum[:4])
}

// keyTag is the 8-byte key id field of the HMBK1 header: the first 8 bytes of
// SHA-256 of the key. KeyID is the hexadecimal form of its first 4 bytes.
func keyTag(key Key) [8]byte {
	sum := sha256.Sum256(key[:])
	var tag [8]byte
	copy(tag[:], sum[:8])
	return tag
}

const (
	recoveryPrefix = "hmrk1"
	// recoveryBodyLen is the length of 34 bytes in base32 without padding.
	recoveryBodyLen = 55
	recoveryCheck   = 2
)

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// FormatRecoveryKey returns the recovery key text: "hmrk1-" followed by the 32
// key bytes and a 2-byte check (the first two bytes of SHA-256 of the key) in
// base32 without padding, lower case, in groups of four separated by "-".
//
// The result is the key. It is shown once to the person at the machine and
// goes nowhere else.
func FormatRecoveryKey(key Key) string {
	sum := sha256.Sum256(key[:])
	raw := make([]byte, 0, KeySize+recoveryCheck)
	raw = append(raw, key[:]...)
	raw = append(raw, sum[:recoveryCheck]...)
	body := strings.ToLower(recoveryEncoding.EncodeToString(raw))
	var b strings.Builder
	b.Grow(len(recoveryPrefix) + len(body) + len(body)/4 + 1)
	b.WriteString(recoveryPrefix)
	for i := 0; i < len(body); i += 4 {
		b.WriteByte('-')
		b.WriteString(body[i:min(i+4, len(body))])
	}
	return b.String()
}

// ParseRecoveryKey reads a recovery key typed by a person. Upper case, white
// space and missing or extra dashes are accepted. A text of the wrong shape is
// ErrRecoveryKeyFormat; a text of the right shape whose check does not match
// (a mistyped character) is ErrRecoveryKeyCheck. Neither error contains the
// text.
func ParseRecoveryKey(text string) (Key, error) {
	if len(text) > 512 {
		return Key{}, ErrRecoveryKeyFormat
	}
	var b strings.Builder
	for _, r := range text {
		switch {
		case unicode.IsSpace(r), unicode.Is(unicode.Pd, r):
			// Spaces, line ends and every kind of dash are separators.
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteRune(r)
		}
	}
	s := b.String()
	if !strings.HasPrefix(s, recoveryPrefix) {
		return Key{}, ErrRecoveryKeyFormat
	}
	body := s[len(recoveryPrefix):]
	if len(body) != recoveryBodyLen {
		return Key{}, ErrRecoveryKeyFormat
	}
	raw, err := recoveryEncoding.DecodeString(strings.ToUpper(body))
	if err != nil || len(raw) != KeySize+recoveryCheck {
		return Key{}, ErrRecoveryKeyFormat
	}
	// 55 characters carry 275 bits for 272: the three spare bits must be
	// zero, so that one key has exactly one text.
	if strings.ToLower(recoveryEncoding.EncodeToString(raw)) != body {
		return Key{}, ErrRecoveryKeyFormat
	}
	var key Key
	copy(key[:], raw[:KeySize])
	sum := sha256.Sum256(key[:])
	if subtle.ConstantTimeCompare(sum[:recoveryCheck], raw[KeySize:]) != 1 {
		return Key{}, ErrRecoveryKeyCheck
	}
	return key, nil
}

// maxKeyFileBytes bounds what LoadKey reads.
const maxKeyFileBytes = 256

// SaveKey writes key to path for scheduled runs, readable by its owner only
// (mode 0600). The file holds the recovery key text and a line end.
//
// The file appears complete or not at all: the content is written to a
// temporary file in the same directory, flushed to disk and then linked to
// path. If anything already exists at path (a key, a symbolic link, anything)
// SaveKey returns ErrKeyExists and changes nothing: replacing a key would make
// every existing archive unreadable.
func SaveKey(path string, key Key) error {
	if key.IsZero() {
		return ErrZeroKey
	}
	dir := filepath.Dir(path)
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("backup: save key: %w", err)
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp-"+hex.EncodeToString(suffix[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("backup: save key: create temporary file: %w", err)
	}
	fail := func(step string, err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("backup: save key: %s: %w", step, err)
	}
	// The umask may only have removed bits; make the mode exact.
	if err := f.Chmod(0o600); err != nil {
		return fail("chmod", err)
	}
	if _, err := f.WriteString(FormatRecoveryKey(key) + "\n"); err != nil {
		return fail("write", err)
	}
	if err := f.Sync(); err != nil {
		return fail("fsync", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("backup: save key: close: %w", err)
	}
	// link(2) fails if path exists and never follows a symbolic link at path:
	// this is the atomic "create only if absent".
	err = os.Link(tmp, path)
	_ = os.Remove(tmp)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrKeyExists
		}
		var le *os.LinkError
		if errors.As(err, &le) {
			err = le.Err
		}
		return fmt.Errorf("backup: save key: link into place: %w", err)
	}
	return syncDir(dir)
}

// LoadKey reads the key file written by SaveKey. A missing file is ErrNoKey.
// The file is refused if it is a symbolic link, is not a regular file, is not
// owned by ownerUID (0 in production; tests pass their own uid) or grants any
// permission to group or others. The checks are made on the opened file, so
// the file that is checked is the file that is read.
func LoadKey(path string, ownerUID uint32) (Key, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Key{}, ErrNoKey
		}
		return Key{}, fmt.Errorf("backup: the key file cannot be opened (a symbolic link is not accepted): %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Key{}, fmt.Errorf("backup: key file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return Key{}, fmt.Errorf("backup: key file %s is not a regular file", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != ownerUID {
		return Key{}, fmt.Errorf("backup: key file %s is not owned by uid %d", path, ownerUID)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return Key{}, fmt.Errorf("backup: key file %s is accessible by group or others", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil {
		return Key{}, fmt.Errorf("backup: read key file: %w", err)
	}
	if len(data) > maxKeyFileBytes {
		return Key{}, fmt.Errorf("backup: key file %s is too large", path)
	}
	key, err := ParseRecoveryKey(string(data))
	if err != nil {
		return Key{}, fmt.Errorf("backup: key file %s is damaged: %w", path, err)
	}
	return key, nil
}

// syncDir fsyncs a directory so that a link, rename or unlink inside it is
// durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("backup: open directory for fsync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("backup: fsync directory: %w", err)
	}
	return nil
}
