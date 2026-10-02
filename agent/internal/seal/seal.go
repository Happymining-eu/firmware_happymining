// Package seal implements the machine side of sealed secrets
// (docs/appliance.md, section 5).
//
// A secret (a NAS password, an API key) is encrypted for one machine with the
// machine's public key. Whoever knows the public key can seal; only the
// machine's privileged helper, which holds the private key in a root-only
// file, can open. The control plane stores and forwards sealed values and has
// no key to open them.
//
//	public key = "hmk1." + base64url_nopad( uncompressed P-256 point, 65 bytes )
//	blob       = "hmseal1." + base64url_nopad( ephemeral_public(65) || AES-256-GCM ciphertext || tag(16) )
//	key        = HKDF-SHA256( ikm  = ECDH(ephemeral_private, machine_public),
//	                          salt = ephemeral_public(65) || machine_public(65),
//	                          info = "happymining-seal-v1", length = 32 )
//	nonce      = 12 zero bytes (each key is used once)
//	AAD        = the secret's name, UTF-8
//	plaintext  = 1 to 4096 bytes
//
// The reference implementation is api/happymining/sealing.py and the shared
// test vectors are appliance/testdata/seal-vectors.json.
//
// Nothing in this package logs, and no error it returns contains a
// plaintext, a sealed value or key material.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
)

// Format constants fixed by the contract.
const (
	// SealedPrefix starts every sealed value.
	SealedPrefix = "hmseal1."
	// PublicKeyPrefix starts every machine public key.
	PublicKeyPrefix = "hmk1."
	// MaxPlaintextBytes is the largest secret that can be sealed.
	MaxPlaintextBytes = 4096
	// MaxNameLen is the longest secret name.
	MaxNameLen = 63

	sealInfo = "happymining-seal-v1"
	pointLen = 65 // uncompressed SEC 1 point: 0x04 || X || Y
	tagLen   = 16
	keyLen   = 32
	nonceLen = 12

	// pemType is the PEM block type of the key file (PKCS #8).
	pemType = "PRIVATE KEY"
	// maxKeyFileBytes bounds the key file; a P-256 PKCS #8 key in PEM is
	// about 240 bytes.
	maxKeyFileBytes = 4096
)

// RootUID is the owner Load and LoadOrCreate insist on.
const RootUID = 0

// Errors returned by this package. They are deliberately coarse: a caller
// reports "unreadable" or "missing", never why in detail.
var (
	// ErrName is returned for a secret name outside ^[a-z][a-z0-9_.-]{0,62}$.
	ErrName = errors.New("secret names are a lower-case letter followed by up to 62 lower-case letters, digits, dots, dashes or underscores")
	// ErrMalformed is returned for a value that is not shaped like a sealed
	// blob (prefix, encoding, length, ephemeral point).
	ErrMalformed = errors.New("the value is not sealed for a machine")
	// ErrOpen is returned when a well-formed blob does not open: it was
	// sealed for another key, under another name, or it was altered.
	ErrOpen = errors.New("the sealed value does not open with this machine's key under this name")
	// ErrPublicKey is returned for a malformed machine public key.
	ErrPublicKey = errors.New("not a valid machine sealing key")
	// ErrPlaintextSize is returned by Seal for an empty or oversized secret.
	ErrPlaintextSize = fmt.Errorf("a secret is 1 to %d bytes", MaxPlaintextBytes)
)

var reName = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,62}$`)

// ValidName reports whether name is a valid secret name.
func ValidName(name string) bool { return reName.MatchString(name) }

// PrivateKey is a machine's sealing key pair. The private part cannot be
// read back through this type, and formatting a PrivateKey with any fmt verb
// prints a fixed marker instead of its fields.
type PrivateKey struct {
	key *ecdh.PrivateKey
	pub []byte // uncompressed point, pointLen bytes
}

// Format implements fmt.Formatter so that no verb (%v, %+v, %#v, %x, …) can
// print the private scalar.
func (PrivateKey) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "seal.PrivateKey(redacted)") }

// Generate creates a new key pair from the operating system's random source.
func Generate() (*PrivateKey, error) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate sealing key: %w", err)
	}
	return fromECDH(key), nil
}

func fromECDH(key *ecdh.PrivateKey) *PrivateKey {
	return &PrivateKey{key: key, pub: key.PublicKey().Bytes()}
}

// Public returns the public key in its wire form, "hmk1.…". It is what the
// machine reports in its heartbeat.
func (k *PrivateKey) Public() string {
	return PublicKeyPrefix + base64.RawURLEncoding.EncodeToString(k.pub)
}

// Open decrypts a sealed value that was sealed for this key under name. The
// name is authenticated: a value sealed as "nas.docs.password" opens under
// no other name. The caller owns the returned plaintext and should Wipe it
// when done.
//
// It returns ErrName, ErrMalformed or ErrOpen.
func (k *PrivateKey) Open(name, sealed string) ([]byte, error) {
	if !ValidName(name) {
		return nil, ErrName
	}
	ephemeral, ciphertext, err := parseSealed(sealed)
	if err != nil {
		return nil, err
	}
	shared, err := k.key.ECDH(ephemeral)
	if err != nil {
		return nil, ErrOpen
	}
	defer Wipe(shared)
	aead, err := newAEAD(shared, ephemeral.Bytes(), k.pub)
	if err != nil {
		return nil, ErrOpen
	}
	plaintext, err := aead.Open(nil, make([]byte, nonceLen), ciphertext, []byte(name))
	if err != nil {
		return nil, ErrOpen
	}
	return plaintext, nil
}

// Seal encrypts plaintext under name for the machine that owns publicKey
// ("hmk1.…"). It is used on the machine for secrets entered locally, and by
// tests. It returns ErrName, ErrPlaintextSize or ErrPublicKey.
func Seal(publicKey, name string, plaintext []byte) (string, error) {
	if !ValidName(name) {
		return "", ErrName
	}
	if len(plaintext) < 1 || len(plaintext) > MaxPlaintextBytes {
		return "", ErrPlaintextSize
	}
	machine, err := parsePublicKey(publicKey)
	if err != nil {
		return "", err
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ephemeral key: %w", err)
	}
	return sealWith(ephemeral, machine, name, plaintext)
}

// sealWith does the sealing proper. It applies no bound to the plaintext so
// that tests can build blobs the format forbids.
func sealWith(ephemeral *ecdh.PrivateKey, machine *ecdh.PublicKey, name string, plaintext []byte) (string, error) {
	shared, err := ephemeral.ECDH(machine)
	if err != nil {
		return "", ErrPublicKey
	}
	defer Wipe(shared)
	ephemeralPublic := ephemeral.PublicKey().Bytes()
	aead, err := newAEAD(shared, ephemeralPublic, machine.Bytes())
	if err != nil {
		return "", errors.New("cannot derive the sealing key")
	}
	blob := make([]byte, 0, pointLen+len(plaintext)+tagLen)
	blob = append(blob, ephemeralPublic...)
	blob = aead.Seal(blob, make([]byte, nonceLen), plaintext, []byte(name))
	return SealedPrefix + base64.RawURLEncoding.EncodeToString(blob), nil
}

// newAEAD derives the one-time AES-256-GCM key of the format.
func newAEAD(shared, ephemeralPublic, machinePublic []byte) (cipher.AEAD, error) {
	salt := make([]byte, 0, 2*pointLen)
	salt = append(salt, ephemeralPublic...)
	salt = append(salt, machinePublic...)
	key, err := hkdf.Key(sha256.New, shared, salt, sealInfo, keyLen)
	if err != nil {
		return nil, err
	}
	defer Wipe(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// CheckSealed reports whether value is shaped like a sealed blob: the prefix,
// base64url without padding, the length bounds and an ephemeral point that is
// on the curve. It needs no key and proves nothing about the content. It
// returns nil or ErrMalformed.
func CheckSealed(value string) error {
	_, _, err := parseSealed(value)
	return err
}

// CheckPublicKey reports whether value is a well-formed machine public key
// ("hmk1." followed by an uncompressed P-256 point that is on the curve). It
// returns nil or ErrPublicKey.
func CheckPublicKey(value string) error {
	_, err := parsePublicKey(value)
	return err
}

// Wipe overwrites b with zeros. Use it on plaintexts returned by Open.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func parseSealed(value string) (*ecdh.PublicKey, []byte, error) {
	maxEncoded := len(SealedPrefix) + base64.RawURLEncoding.EncodedLen(pointLen+tagLen+MaxPlaintextBytes)
	if len(value) > maxEncoded || len(value) <= len(SealedPrefix) || value[:len(SealedPrefix)] != SealedPrefix {
		return nil, nil, ErrMalformed
	}
	raw, err := decodeBase64URL(value[len(SealedPrefix):])
	if err != nil {
		return nil, nil, ErrMalformed
	}
	if len(raw) < pointLen+tagLen+1 || len(raw) > pointLen+tagLen+MaxPlaintextBytes || raw[0] != 0x04 {
		return nil, nil, ErrMalformed
	}
	// NewPublicKey rejects a point that is not on the curve and the point at
	// infinity.
	ephemeral, err := ecdh.P256().NewPublicKey(raw[:pointLen])
	if err != nil {
		return nil, nil, ErrMalformed
	}
	return ephemeral, raw[pointLen:], nil
}

func parsePublicKey(value string) (*ecdh.PublicKey, error) {
	if len(value) <= len(PublicKeyPrefix) || len(value) > len(PublicKeyPrefix)+base64.RawURLEncoding.EncodedLen(pointLen) ||
		value[:len(PublicKeyPrefix)] != PublicKeyPrefix {
		return nil, ErrPublicKey
	}
	raw, err := decodeBase64URL(value[len(PublicKeyPrefix):])
	if err != nil || len(raw) != pointLen || raw[0] != 0x04 {
		return nil, ErrPublicKey
	}
	key, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, ErrPublicKey
	}
	return key, nil
}

// decodeBase64URL accepts the URL-safe alphabet without padding and nothing
// else. The standard decoder alone would skip CR and LF.
func decodeBase64URL(text string) ([]byte, error) {
	if text == "" {
		return nil, errors.New("empty")
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
		if !ok {
			return nil, errors.New("not base64url")
		}
	}
	return base64.RawURLEncoding.DecodeString(text)
}

// --- the key file ------------------------------------------------------------
//
// On disk the key is one PEM block of type "PRIVATE KEY" holding the PKCS #8
// encoding of the P-256 private key (the format `openssl genpkey -algorithm
// EC -pkeyopt ec_paramgen_curve:P-256` writes), mode 0600.

// Load reads the machine's sealing key from path, which must be a regular
// file owned by root that neither group nor others can read or write. A
// symbolic link is refused. A missing file is reported with an error that
// matches fs.ErrNotExist.
//
// The directories above path are not examined: they must not be writable by
// anyone but root.
func Load(path string) (*PrivateKey, error) { return LoadOwnedBy(path, RootUID) }

// LoadOwnedBy is Load with the uid that must own the file. Production code
// passes 0; tests pass their own uid.
func LoadOwnedBy(path string, ownerUID uint32) (*PrivateKey, error) {
	data, err := readKeyFile(path, ownerUID)
	if err != nil {
		return nil, err
	}
	defer Wipe(data)
	key, err := parsePEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s does not hold a sealing key", path)
	}
	return key, nil
}

// LoadOrCreate returns the machine's sealing key, creating it when path does
// not exist yet. The file is created with mode 0600, complete or not at all
// (temporary file, fsync, hard link into place), and an existing file is
// never overwritten: if it cannot be used, the error says so and the file is
// left alone. Only root can create the key. The checks of Load apply.
func LoadOrCreate(path string) (*PrivateKey, error) { return LoadOrCreateOwnedBy(path, RootUID) }

// LoadOrCreateOwnedBy is LoadOrCreate with the uid that must own the file.
// Creating the file requires the process to run as that uid.
func LoadOrCreateOwnedBy(path string, ownerUID uint32) (*PrivateKey, error) {
	key, err := LoadOwnedBy(path, ownerUID)
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return key, err
	}
	if uint32(os.Geteuid()) != ownerUID {
		return nil, fmt.Errorf("%s does not exist and can only be created by uid %d", path, ownerUID)
	}
	key, err = Generate()
	if err != nil {
		return nil, err
	}
	encoded, err := key.marshalPEM()
	if err != nil {
		return nil, err
	}
	defer Wipe(encoded)
	if err := createExclusive(path, encoded); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	// Read back what is on disk: after a lost race it is the other
	// process's key, and in every case it proves the file can be loaded.
	return LoadOwnedBy(path, ownerUID)
}

// readKeyFile opens path without following a symbolic link and checks the
// opened file, so the file that is checked is the file that is read.
func readKeyFile(path string, ownerUID uint32) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("sealing key %s: %w", path, fs.ErrNotExist)
		}
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
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != ownerUID {
		return nil, fmt.Errorf("%s is not owned by uid %d", path, ownerUID)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has permissions %04o; a sealing key readable or writable by group or others is refused (expected 0600)",
			path, fi.Mode().Perm())
	}
	if fi.Size() > maxKeyFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxKeyFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxKeyFileBytes {
		Wipe(data)
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxKeyFileBytes)
	}
	return data, nil
}

// createExclusive writes data to a new file at path with mode 0600. It fails
// with an error matching fs.ErrExist when path already exists (whatever it
// is, a dangling symbolic link included) and never leaves a partial file.
func createExclusive(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	fail := func(err error) error {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		return fail(fmt.Errorf("chmod temporary file: %w", err))
	}
	if _, err := f.Write(data); err != nil {
		return fail(fmt.Errorf("write temporary file: %w", err))
	}
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("fsync temporary file: %w", err))
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	// link(2) refuses to replace anything, which rename(2) would not.
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s: %w", path, fs.ErrExist)
		}
		return fmt.Errorf("link the sealing key into place: %w", err)
	}
	return fsx.SyncDir(dir)
}

func (k *PrivateKey) marshalPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.key)
	if err != nil {
		return nil, errors.New("cannot encode the sealing key")
	}
	defer Wipe(der)
	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}), nil
}

func parsePEM(data []byte) (*PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != pemType || len(block.Headers) != 0 || len(trimNewlines(rest)) != 0 {
		return nil, errors.New("not a PKCS #8 PEM block")
	}
	defer Wipe(block.Bytes)
	return parsePKCS8(block.Bytes)
}

func parsePKCS8(der []byte) (*PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("not a PKCS #8 private key")
	}
	ec, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an elliptic-curve key")
	}
	key, err := ec.ECDH()
	if err != nil || key.Curve() != ecdh.P256() {
		return nil, errors.New("not a P-256 key")
	}
	return fromECDH(key), nil
}

func trimNewlines(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
