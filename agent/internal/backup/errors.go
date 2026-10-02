package backup

import (
	"errors"
	"fmt"
)

// Key errors.
var (
	// ErrRecoveryKeyFormat: the text is not shaped like a recovery key.
	ErrRecoveryKeyFormat = errors.New("backup: this is not a recovery key (expected hmrk1- followed by 55 letters and digits)")
	// ErrRecoveryKeyCheck: the text is shaped like a recovery key but its
	// check does not match: at least one character was mistyped.
	ErrRecoveryKeyCheck = errors.New("backup: the recovery key check does not match: a character was mistyped")
	// ErrKeyExists: SaveKey found something at the key path and left it alone.
	ErrKeyExists = errors.New("backup: a backup key already exists and is not overwritten")
	// ErrNoKey: there is no key file.
	ErrNoKey = errors.New("backup: no backup key on this machine")
	// ErrZeroKey: the all-zero key is refused; it is what an uninitialised
	// Key looks like.
	ErrZeroKey = errors.New("backup: the key is not initialised")
)

// Stream errors (HMBK1). None of them carries key material or plaintext.
var (
	// ErrBadHeader: the input does not start with a valid HMBK1 header.
	ErrBadHeader = errors.New("backup: not an HMBK1 archive (bad header)")
	// ErrWrongKey: the archive names another key than the one supplied. It is
	// reported before anything is decrypted. See KeyMismatchError.
	ErrWrongKey = errors.New("backup: this key is not the key of the archive")
	// ErrKeyOrHeader: the key id matches but the first chunk does not
	// authenticate: the header (key id, salt or chunk size) was altered, the
	// key is not the right one after all, or the first chunk is damaged.
	// Nothing was decrypted.
	ErrKeyOrHeader = errors.New("backup: the archive does not open with this key (altered header, wrong key or damaged start)")
	// ErrCorrupt: a later chunk does not authenticate: it was altered, moved
	// or repeated.
	ErrCorrupt = errors.New("backup: the archive is damaged (a chunk is altered, moved or repeated)")
	// ErrTruncated: the stream ends before its final chunk.
	ErrTruncated = errors.New("backup: the archive is incomplete (it ends before its final chunk)")
	// ErrTrailingData: something follows the final chunk.
	ErrTrailingData = errors.New("backup: the archive has data after its final chunk")
	// ErrChunkLength: a chunk announces a length the format does not allow
	// (longer than chunk_size plus the tag, shorter than the tag, or a
	// non-final chunk that is not full).
	ErrChunkLength = errors.New("backup: the archive has a chunk of invalid length")
	// ErrClosed: write after Close.
	ErrClosed = errors.New("backup: write to a closed archive")
)

// Archive errors.
var (
	// ErrBadArchive: the decrypted content is not a gzip(tar) with a valid
	// manifest.
	ErrBadArchive = errors.New("backup: invalid archive content")
	// ErrUnsafePath: an entry name is absolute, contains "..", or goes through
	// something that is not a real directory (a symbolic link, for instance).
	ErrUnsafePath = errors.New("backup: unsafe path")
	// ErrUnsupportedEntry: an entry is a hard link, a device node, a FIFO or
	// any other type this format does not store.
	ErrUnsupportedEntry = errors.New("backup: entry type not allowed")
	// ErrTooManyEntries: the archive has more entries than allowed.
	ErrTooManyEntries = errors.New("backup: the archive has too many entries")
	// ErrTooLarge: the archive expands to more bytes than allowed.
	ErrTooLarge = errors.New("backup: the archive expands beyond the size limit")
	// ErrExists: an entry would overwrite something that already exists.
	ErrExists = errors.New("backup: the entry already exists and is not overwritten")
	// ErrInvalidItem: an Item is not acceptable (name, path or kind).
	ErrInvalidItem = errors.New("backup: invalid item")
	// ErrSourceChanged: a source file changed while it was being read.
	ErrSourceChanged = errors.New("backup: a source changed while it was being saved")
)

// Destination errors.
var (
	// ErrInvalidName: the name is not an archive name
	// (hm-backup-<machine id>-<YYYYMMDDTHHMMSSZ>.hmbk).
	ErrInvalidName = errors.New("backup: not an archive name")
	// ErrNotFound: the destination has no archive of that name.
	ErrNotFound = errors.New("backup: no such archive at the destination")
	// ErrInvalidConfig: a destination or run option is not acceptable.
	ErrInvalidConfig = errors.New("backup: invalid configuration")
	// ErrTooManyParts: the archive needs more than 10000 S3 parts of the
	// configured size.
	ErrTooManyParts = errors.New("backup: the archive needs more than 10000 parts; a larger part size is required")
)

// KeyMismatchError is the detail of ErrWrongKey. Key ids are not secret: the
// machine reports its own in the heartbeat.
type KeyMismatchError struct {
	// ArchiveKeyID is the key id the archive was made with (8 hex characters).
	ArchiveKeyID string
	// KeyID is the id of the key that was supplied.
	KeyID string
}

func (e *KeyMismatchError) Error() string {
	return fmt.Sprintf("backup: the archive was made with key %s, not with key %s", e.ArchiveKeyID, e.KeyID)
}

// Is makes errors.Is(err, ErrWrongKey) true.
func (e *KeyMismatchError) Is(target error) bool { return target == ErrWrongKey }

// EntryError says which entry an archive error is about. Error() names the
// item only: Name, the path inside the archive, is a file name of the saved
// data and stays out of anything that could be reported to the control plane.
// A local tool may print Name.
type EntryError struct {
	// Op is "save" or "restore".
	Op string
	// Item is the logical item name the entry belongs to ("" when unknown).
	Item string
	// Name is the entry's path inside the archive.
	Name string
	Err  error
}

func (e *EntryError) Error() string {
	if e.Item == "" {
		return fmt.Sprintf("backup: %s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("backup: %s item %q: %v", e.Op, e.Item, e.Err)
}

func (e *EntryError) Unwrap() error { return e.Err }
