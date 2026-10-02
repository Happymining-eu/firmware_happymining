// Package release verifies signed firmware release manifests
// (docs/appliance.md, section 9).
//
// A release is the agent package plus a small JSON manifest signed with
// Ed25519. The signature covers the exact bytes of the manifest. The
// privileged helper verifies, in this order: the signature against the keys
// installed with the current package (LoadKeys, Verify), the manifest's
// content (Verify), the package's size and SHA-256 (StageArtifact or
// CheckArtifact) and that the release is an upgrade the installed version may
// take (CheckUpgrade). Nothing here downloads, installs or takes a URL.
//
// The reference implementation is verify_manifest in
// api/happymining/sealing.py and the shared test vector is
// appliance/testdata/release-vector.json. Verify accepts every manifest the
// release tooling produces and the reference accepts. It is stricter than the
// reference for input no release tool writes: the manifest must be UTF-8
// without a byte order mark, NaN and Infinity are not numbers, and "schema"
// must be the integer 1 (the reference also takes 1.0 and true).
package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
)

// Values fixed by the contract.
const (
	// ManifestSchema is the only manifest schema this code understands.
	ManifestSchema = 1
	// Product is the only product a manifest may name.
	Product = "happymining-agent"
	// MaxManifestBytes bounds the signed manifest.
	MaxManifestBytes = 16 * 1024
	// MaxArtifactBytes bounds the package a manifest may describe.
	MaxArtifactBytes = 512 * 1024 * 1024
	// MaxNotesLen is the number of characters of "notes" that are kept.
	MaxNotesLen = 4000
	// KeyFileSuffix is the suffix of release public key files.
	KeyFileSuffix = ".pub"

	maxKeyFiles     = 16
	maxKeyFileBytes = 256
)

// RootUID is the owner LoadKeys insists on.
const RootUID = 0

// Errors a caller may want to tell apart. Verify, CheckArtifact, StageArtifact
// and CheckUpgrade wrap them; test with errors.Is.
var (
	// ErrNoKeys: no release public key is installed, so nothing can be trusted.
	ErrNoKeys = errors.New("no release public key is installed; releases cannot be verified")
	// ErrSignature: the signature is malformed or verifies against no installed key.
	ErrSignature = errors.New("the manifest signature does not verify against any installed release key")
	// ErrManifest: the manifest is signed but its content is not acceptable.
	ErrManifest = errors.New("the manifest is signed but not well formed")
	// ErrArtifact: the package does not match the manifest.
	ErrArtifact = errors.New("the package does not match the manifest")
	// ErrNotAnUpgrade: the release is not newer than the installed version, or
	// the installed version is older than the release's min_upgrade_from.
	ErrNotAnUpgrade = errors.New("the release cannot be installed over the installed version")
	// ErrVersion: a version is not MAJOR.MINOR.PATCH.
	ErrVersion = errors.New("a version is MAJOR.MINOR.PATCH, numbers only")
)

// Version is a release version: three numbers compared numerically.
type Version struct {
	Major, Minor, Patch int
}

var (
	reVersion  = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
	reFilename = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,120}\.deb$`)
	reSHA256   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reInteger  = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
	reBase64   = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
)

// ParseVersion parses "MAJOR.MINOR.PATCH". Each number is 0 to 999999 without
// a sign, a leading zero or anything else around it.
func ParseVersion(text string) (Version, error) {
	m := reVersion.FindStringSubmatch(text)
	if m == nil {
		return Version{}, ErrVersion
	}
	var v Version
	for i, dst := range []*int{&v.Major, &v.Minor, &v.Patch} {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return Version{}, ErrVersion
		}
		*dst = n
	}
	return v, nil
}

// Compare returns -1, 0 or +1 when v is older than, equal to or newer than
// other.
func (v Version) Compare(other Version) int {
	for _, pair := range [3][2]int{{v.Major, other.Major}, {v.Minor, other.Minor}, {v.Patch, other.Patch}} {
		switch {
		case pair[0] < pair[1]:
			return -1
		case pair[0] > pair[1]:
			return 1
		}
	}
	return 0
}

// String returns "MAJOR.MINOR.PATCH".
func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// KeyID returns the identifier of a release public key: the first 16
// hexadecimal characters of the SHA-256 of its 32 bytes.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// Keys is a set of trusted release public keys by key id.
type Keys map[string]ed25519.PublicKey

// ParsePublicKey decodes a release public key: the standard base64 (with
// padding) of the 32-byte Ed25519 public key, as scripts/release-sign.py
// prints it and as key files hold it.
func ParsePublicKey(encoded string) (ed25519.PublicKey, error) {
	if !reBase64.MatchString(encoded) {
		return nil, errors.New("a release public key is 32 bytes, base64 encoded")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("a release public key is 32 bytes, base64 encoded")
	}
	return ed25519.PublicKey(raw), nil
}

// LoadKeys reads the release public keys installed with the package: every
// file named *.pub in dir, each holding the base64 of one key, optionally
// followed by one newline. Other file names are ignored.
//
// dir and every key file must be owned by root and not writable by group or
// others; a key file must be a regular file, not a symbolic link. Anything
// else in the place of a key is an error for the whole set: a damaged trust
// directory yields no keys at all. A missing or empty directory yields an
// empty set and no error, and Verify then refuses everything.
//
// The directories above dir are not examined: they must not be writable by
// anyone but root.
func LoadKeys(dir string) (Keys, error) { return LoadKeysOwnedBy(dir, RootUID) }

// LoadKeysOwnedBy is LoadKeys with the uid that must own the directory and
// the files. Production code passes 0; tests pass their own uid.
func LoadKeysOwnedBy(dir string, ownerUID uint32) (Keys, error) {
	keys := Keys{}
	di, err := os.Lstat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return keys, nil
		}
		return nil, err
	}
	if !di.IsDir() {
		return nil, fmt.Errorf("%s is not a directory (a symbolic link is not accepted)", dir)
	}
	if err := checkOwnerAndMode(dir, di, ownerUID); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), KeyFileSuffix) {
			continue
		}
		if files++; files > maxKeyFiles {
			return nil, fmt.Errorf("%s holds more than %d key files", dir, maxKeyFiles)
		}
		path := filepath.Join(dir, entry.Name())
		data, err := readTrustedFile(path, ownerUID, maxKeyFileBytes)
		if err != nil {
			return nil, err
		}
		key, err := ParsePublicKey(strings.TrimSuffix(string(data), "\n"))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		keys[KeyID(key)] = key
	}
	return keys, nil
}

func checkOwnerAndMode(path string, fi fs.FileInfo, ownerUID uint32) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != ownerUID {
		return fmt.Errorf("%s is not owned by uid %d", path, ownerUID)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others", path)
	}
	return nil
}

// readTrustedFile opens path without following a symbolic link and checks
// the opened file, so the file that is checked is the file that is read.
func readTrustedFile(path string, ownerUID uint32, maxBytes int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be opened (a symbolic link is not accepted): %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if err := checkOwnerAndMode(path, fi, ownerUID); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxBytes)
	}
	return data, nil
}

// Manifest is a verified release manifest.
type Manifest struct {
	// Version of the release, "MAJOR.MINOR.PATCH".
	Version string
	// Filename of the package. It is a plain file name: no directory part.
	Filename string
	// Size of the package in bytes.
	Size int64
	// SHA256 of the package, 64 lower-case hexadecimal characters.
	SHA256 string
	// Notes are the release notes, cut to MaxNotesLen characters. They are
	// text for people and are empty when the manifest's "notes" is absent or
	// not a string.
	Notes string
	// MinUpgradeFrom is the oldest installed version that may take this
	// release; "0.0.0" when the manifest does not say.
	MinUpgradeFrom string
	// KeyID identifies the key whose signature verified.
	KeyID string
	// Raw is the signed manifest, byte for byte.
	Raw []byte
}

// Verify checks the signature over the exact manifest bytes against keys and,
// only when it verifies, the manifest's content: schema 1, product
// "happymining-agent", a well-formed version and min_upgrade_from, an
// artifact with a plain *.deb file name, a size of 1 byte to 512 MiB and a
// SHA-256. Unknown keys in the manifest are ignored, as in the reference
// implementation. signatureB64 is the standard base64 (with padding, no
// white space) of the 64-byte signature.
//
// The error wraps ErrNoKeys, ErrSignature or ErrManifest.
func Verify(manifest []byte, signatureB64 string, keys Keys) (*Manifest, error) {
	if len(keys) == 0 {
		return nil, ErrNoKeys
	}
	if len(manifest) > MaxManifestBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrManifest, MaxManifestBytes)
	}
	if !reBase64.MatchString(signatureB64) {
		return nil, fmt.Errorf("%w: the signature is not base64", ErrSignature)
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, fmt.Errorf("%w: the signature is not base64", ErrSignature)
	}
	signer := ""
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		key := keys[id]
		// ed25519.Verify panics on a key of the wrong size and returns false
		// for a signature of the wrong size.
		if len(key) == ed25519.PublicKeySize && ed25519.Verify(key, manifest, signature) {
			signer = KeyID(key)
			break
		}
	}
	if signer == "" {
		return nil, ErrSignature
	}
	m, err := parseManifest(manifest)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrManifest, err.Error())
	}
	m.KeyID = signer
	m.Raw = append([]byte(nil), manifest...)
	return m, nil
}

func parseManifest(raw []byte) (*Manifest, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, errors.New("not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the JSON object")
	}
	if doc == nil {
		return nil, errors.New("not a JSON object")
	}
	if n, ok := integer(doc["schema"]); !ok || n != ManifestSchema {
		return nil, errors.New("schema")
	}
	if product, ok := doc["product"].(string); !ok || product != Product {
		return nil, errors.New("product")
	}
	version, ok := doc["version"].(string)
	if !ok {
		return nil, errors.New("version")
	}
	if _, err := ParseVersion(version); err != nil {
		return nil, errors.New("version")
	}
	minFrom := "0.0.0"
	if value, present := doc["min_upgrade_from"]; present {
		text, ok := value.(string)
		if !ok {
			return nil, errors.New("min_upgrade_from")
		}
		if _, err := ParseVersion(text); err != nil {
			return nil, errors.New("min_upgrade_from")
		}
		minFrom = text
	}
	artifact, ok := doc["artifact"].(map[string]any)
	if !ok {
		return nil, errors.New("artifact")
	}
	filename, ok := artifact["filename"].(string)
	if !ok || !reFilename.MatchString(filename) {
		return nil, errors.New("filename")
	}
	size, ok := integer(artifact["size"])
	if !ok || size <= 0 || size > MaxArtifactBytes {
		return nil, errors.New("size")
	}
	digest, ok := artifact["sha256"].(string)
	if !ok || !reSHA256.MatchString(digest) {
		return nil, errors.New("sha256")
	}
	notes, _ := doc["notes"].(string)
	if utf8.RuneCountInString(notes) > MaxNotesLen {
		notes = string([]rune(notes)[:MaxNotesLen])
	}
	return &Manifest{
		Version:        version,
		Filename:       filename,
		Size:           size,
		SHA256:         digest,
		Notes:          notes,
		MinUpgradeFrom: minFrom,
	}, nil
}

// integer accepts a JSON integer: digits with an optional sign, no fraction,
// no exponent, and within int64.
func integer(v any) (int64, bool) {
	number, ok := v.(json.Number)
	if !ok || !reInteger.MatchString(number.String()) {
		return 0, false
	}
	n, err := strconv.ParseInt(number.String(), 10, 64)
	return n, err == nil
}

// CheckArtifact checks that the file at path is the package the manifest
// describes: a regular file (a symbolic link is refused), of exactly the
// manifest's size, with the manifest's SHA-256. The error wraps ErrArtifact
// when the file is there but is not that package.
//
// A check is only worth something if the file cannot change afterwards. The
// helper must not check a file in a directory the unprivileged agent can
// write and then install it by path: use StageArtifact, which copies the
// bytes into a directory only root can write while checking them.
func CheckArtifact(path string, m *Manifest) error {
	f, err := openArtifact(path, m)
	if err != nil {
		return err
	}
	defer f.Close()
	return hashArtifact(f, io.Discard, m)
}

// StageArtifact copies the package at src into dstDir under the manifest's
// file name, checking size and SHA-256 on the bytes it writes, and returns
// the path of the copy. On any failure nothing is left in dstDir. The copy
// has mode 0600 and replaces an earlier copy of the same name.
//
// dstDir must be a directory that only root can write; the caller creates it.
// What is installed afterwards is the returned path, never src.
func StageArtifact(src, dstDir string, m *Manifest) (string, error) {
	in, err := openArtifact(src, m)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.CreateTemp(dstDir, "."+m.Filename+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("create temporary file: %w", err)
	}
	tmp := out.Name()
	fail := func(err error) (string, error) {
		_ = out.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if err := out.Chmod(0o600); err != nil {
		return fail(fmt.Errorf("chmod temporary file: %w", err))
	}
	if err := hashArtifact(in, out, m); err != nil {
		return fail(err)
	}
	if err := out.Sync(); err != nil {
		return fail(fmt.Errorf("fsync temporary file: %w", err))
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("close temporary file: %w", err)
	}
	dst := filepath.Join(dstDir, m.Filename)
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("rename into place: %w", err)
	}
	if err := fsx.SyncDir(dstDir); err != nil {
		return "", err
	}
	return dst, nil
}

func openArtifact(path string, m *Manifest) (*os.File, error) {
	if m == nil || !reFilename.MatchString(m.Filename) || !reSHA256.MatchString(m.SHA256) || m.Size <= 0 || m.Size > MaxArtifactBytes {
		return nil, errors.New("the manifest was not produced by Verify")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be opened (a symbolic link is not accepted): %w", path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrArtifact, path)
	}
	if fi.Size() != m.Size {
		_ = f.Close()
		return nil, fmt.Errorf("%w: size %d, the manifest says %d", ErrArtifact, fi.Size(), m.Size)
	}
	return f, nil
}

// hashArtifact reads at most one byte more than the manifest's size from r,
// writes what it reads to w and compares size and SHA-256.
func hashArtifact(r io.Reader, w io.Writer, m *Manifest) error {
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(hash, w), io.LimitReader(r, m.Size+1))
	if err != nil {
		return fmt.Errorf("read the package: %w", err)
	}
	if n != m.Size {
		return fmt.Errorf("%w: size differs from the manifest's %d", ErrArtifact, m.Size)
	}
	if hex.EncodeToString(hash.Sum(nil)) != m.SHA256 {
		return fmt.Errorf("%w: SHA-256 differs", ErrArtifact)
	}
	return nil
}

// CheckUpgrade checks that the release may be installed over the installed
// version: the release is strictly newer (no downgrade, no reinstall) and the
// installed version is at least the release's min_upgrade_from. The error
// wraps ErrNotAnUpgrade, or ErrVersion when installed is not a version.
func CheckUpgrade(installed string, m *Manifest) error {
	if m == nil {
		return errors.New("the manifest was not produced by Verify")
	}
	have, err := ParseVersion(installed)
	if err != nil {
		return fmt.Errorf("installed version: %w", err)
	}
	target, err := ParseVersion(m.Version)
	if err != nil {
		return fmt.Errorf("release version: %w", err)
	}
	minFrom, err := ParseVersion(m.MinUpgradeFrom)
	if err != nil {
		return fmt.Errorf("min_upgrade_from: %w", err)
	}
	if target.Compare(have) <= 0 {
		return fmt.Errorf("%w: release %s is not newer than the installed %s", ErrNotAnUpgrade, target, have)
	}
	if have.Compare(minFrom) < 0 {
		return fmt.Errorf("%w: release %s needs at least %s installed, this machine has %s", ErrNotAnUpgrade, target, minFrom, have)
	}
	return nil
}
