package seal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// vectorsPath is the file shared with the Python and JavaScript
// implementations.
const vectorsPath = "../../../appliance/testdata/seal-vectors.json"

type vectorFile struct {
	PKCS8B64  string `json:"machine_private_key_pkcs8_b64"`
	ScalarHex string `json:"machine_private_scalar_hex"`
	Public    string `json:"machine_public_key"`
	Vectors   []struct {
		Name         string `json:"name"`
		PlaintextB64 string `json:"plaintext_b64"`
		Sealed       string `json:"sealed"`
	} `json:"vectors"`
	MustFail []struct {
		Why    string `json:"why"`
		Name   string `json:"name"`
		Sealed string `json:"sealed"`
	} `json:"must_fail"`
}

func loadVectors(t *testing.T) (vectorFile, *PrivateKey) {
	t.Helper()
	data, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(v.PKCS8B64)
	if err != nil {
		t.Fatal(err)
	}
	key, err := parsePKCS8(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Vectors) == 0 || len(v.MustFail) == 0 {
		t.Fatal("the vector file is empty")
	}
	return v, key
}

func mustGenerate(t *testing.T) *PrivateKey {
	t.Helper()
	key, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func myUID() uint32 { return uint32(os.Getuid()) }

func TestVectorKeyEncodingsAgree(t *testing.T) {
	v, key := loadVectors(t)
	if key.Public() != v.Public {
		t.Fatalf("public key from PKCS #8 = %s, want %s", key.Public(), v.Public)
	}
	scalar, err := hex.DecodeString(v.ScalarHex)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	if got := fromECDH(raw).Public(); got != v.Public {
		t.Fatalf("public key from the raw scalar = %s, want %s", got, v.Public)
	}
	if err := CheckPublicKey(v.Public); err != nil {
		t.Fatalf("the vector public key is refused: %v", err)
	}
}

func TestEveryVectorOpens(t *testing.T) {
	v, key := loadVectors(t)
	for _, vec := range v.Vectors {
		want, err := base64.StdEncoding.DecodeString(vec.PlaintextB64)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckSealed(vec.Sealed); err != nil {
			t.Errorf("%s: CheckSealed: %v", vec.Name, err)
		}
		got, err := key.Open(vec.Name, vec.Sealed)
		if err != nil {
			t.Errorf("%s: %v", vec.Name, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: wrong plaintext", vec.Name)
		}
	}
}

func TestEveryMustFailCaseFails(t *testing.T) {
	v, key := loadVectors(t)
	for _, c := range v.MustFail {
		if got, err := key.Open(c.Name, c.Sealed); err == nil {
			t.Errorf("%s: opened to %d bytes, must fail", c.Why, len(got))
		}
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := mustGenerate(t)
	for _, size := range []int{1, 2, 31, 32, 33, 1000, MaxPlaintextBytes} {
		plaintext := make([]byte, size)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatal(err)
		}
		sealed, err := Seal(key.Public(), "nas.docs.password", plaintext)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if err := CheckSealed(sealed); err != nil {
			t.Fatalf("size %d: CheckSealed refuses our own blob: %v", size, err)
		}
		got, err := key.Open("nas.docs.password", sealed)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("size %d: round trip changed the plaintext", size)
		}
	}
	// Two seals of the same secret differ: the ephemeral key is fresh.
	a, _ := Seal(key.Public(), "x", []byte("same"))
	b, _ := Seal(key.Public(), "x", []byte("same"))
	if a == b {
		t.Fatal("two seals of the same secret are identical")
	}
}

func TestOpenRefusesOtherKeyAndOtherName(t *testing.T) {
	key, other := mustGenerate(t), mustGenerate(t)
	sealed, err := Seal(key.Public(), "nas.docs.password", []byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Open("nas.docs.password", sealed); !errors.Is(err, ErrOpen) {
		t.Fatalf("a blob sealed for another key: err = %v, want ErrOpen", err)
	}
	if _, err := key.Open("nas.other.password", sealed); !errors.Is(err, ErrOpen) {
		t.Fatalf("a blob opened under another name: err = %v, want ErrOpen", err)
	}
	if _, err := key.Open("Not A Name", sealed); !errors.Is(err, ErrName) {
		t.Fatalf("an invalid name: err = %v, want ErrName", err)
	}
	if _, err := key.Open("nas.docs.password", sealed); err != nil {
		t.Fatalf("the right key and name must open: %v", err)
	}
}

func TestTamperingAnyByteFails(t *testing.T) {
	key := mustGenerate(t)
	sealed, err := Seal(key.Public(), "ai.answer.api_key", []byte("sk-test-0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, SealedPrefix))
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		for _, bit := range []byte{0x01, 0x80} {
			mutated := append([]byte(nil), raw...)
			mutated[i] ^= bit
			blob := SealedPrefix + base64.RawURLEncoding.EncodeToString(mutated)
			if _, err := key.Open("ai.answer.api_key", blob); err == nil {
				t.Fatalf("flipping bit %#x of byte %d still opens", bit, i)
			}
		}
	}
	// Dropping or adding bytes fails too.
	for _, mutated := range [][]byte{raw[:len(raw)-1], append(append([]byte(nil), raw...), 0)} {
		blob := SealedPrefix + base64.RawURLEncoding.EncodeToString(mutated)
		if _, err := key.Open("ai.answer.api_key", blob); err == nil {
			t.Fatal("a blob of another length still opens")
		}
	}
}

func TestSealRefusesBadInput(t *testing.T) {
	key := mustGenerate(t)
	if _, err := Seal(key.Public(), "x", nil); !errors.Is(err, ErrPlaintextSize) {
		t.Fatalf("empty plaintext: %v", err)
	}
	if _, err := Seal(key.Public(), "x", make([]byte, MaxPlaintextBytes+1)); !errors.Is(err, ErrPlaintextSize) {
		t.Fatalf("oversized plaintext: %v", err)
	}
	for _, name := range []string{"", "X", "1x", "a b", "a/b", "a\n", strings.Repeat("a", 64)} {
		if _, err := Seal(key.Public(), name, []byte("s")); !errors.Is(err, ErrName) {
			t.Errorf("name %q: %v", name, err)
		}
	}
	pub := key.Public()
	notOnCurve := make([]byte, pointLen)
	notOnCurve[0] = 0x04
	notOnCurve[64] = 0x01
	for why, bad := range map[string]string{
		"empty":           "",
		"prefix only":     PublicKeyPrefix,
		"wrong prefix":    "hmk2." + pub[len(PublicKeyPrefix):],
		"truncated":       pub[:len(pub)-4],
		"extended":        pub + "AAAA",
		"padded":          pub + "=",
		"with a newline":  pub + "\n",
		"not on curve":    PublicKeyPrefix + base64.RawURLEncoding.EncodeToString(notOnCurve),
		"compressed":      PublicKeyPrefix + base64.RawURLEncoding.EncodeToString(append([]byte{0x02}, key.pub[1:33]...)),
		"sealed blob":     SealedPrefix + pub[len(PublicKeyPrefix):],
		"standard base64": PublicKeyPrefix + base64.StdEncoding.EncodeToString(key.pub),
	} {
		if _, err := Seal(bad, "x", []byte("s")); !errors.Is(err, ErrPublicKey) {
			t.Errorf("%s: err = %v, want ErrPublicKey", why, err)
		}
		if err := CheckPublicKey(bad); !errors.Is(err, ErrPublicKey) {
			t.Errorf("%s: CheckPublicKey = %v", why, err)
		}
	}
}

// sealUnbounded builds a blob with a plaintext the format does not allow.
func sealUnbounded(t *testing.T, key *PrivateKey, name string, plaintext []byte) string {
	t.Helper()
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealWith(ephemeral, key.key.PublicKey(), name, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func TestOpenRefusesEmptyAndOversizedPlaintext(t *testing.T) {
	key := mustGenerate(t)
	for why, plaintext := range map[string][]byte{
		"empty":     {},
		"oversized": make([]byte, MaxPlaintextBytes+1),
	} {
		sealed := sealUnbounded(t, key, "x", plaintext)
		if err := CheckSealed(sealed); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: CheckSealed = %v, want ErrMalformed", why, err)
		}
		if _, err := key.Open("x", sealed); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: Open = %v, want ErrMalformed", why, err)
		}
	}
	// The bounds themselves are accepted.
	for _, size := range []int{1, MaxPlaintextBytes} {
		if err := CheckSealed(sealUnbounded(t, key, "x", make([]byte, size))); err != nil {
			t.Errorf("size %d: %v", size, err)
		}
	}
}

func TestCheckSealedShape(t *testing.T) {
	v, _ := loadVectors(t)
	good := v.Vectors[0].Sealed
	body := strings.TrimPrefix(good, SealedPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(b []byte) string { return SealedPrefix + base64.RawURLEncoding.EncodeToString(b) }
	offCurve := append([]byte(nil), raw...)
	offCurve[pointLen-1] ^= 0x01 // another Y for the same X is not on the curve
	compressed := append([]byte(nil), raw...)
	compressed[0] = 0x02

	bad := map[string]string{
		"empty":                  "",
		"prefix only":            SealedPrefix,
		"wrong prefix":           "hmseal2." + body,
		"no prefix":              body,
		"upper-case prefix":      "HMSEAL1." + body,
		"clear text":             "hunter2",
		"padding":                good + "=",
		"standard alphabet":      SealedPrefix + strings.NewReplacer("-", "+", "_", "/").Replace(body),
		"space inside":           SealedPrefix + body[:10] + " " + body[10:],
		"newline at the end":     good + "\n",
		"newline inside":         SealedPrefix + body[:10] + "\n" + body[10:],
		"impossible length":      encode(raw[:84]) + "A", // 4n+1 characters encode nothing
		"too short for a tag":    encode(raw[:pointLen+tagLen]),
		"point only":             encode(raw[:pointLen]),
		"too long":               encode(append(append([]byte(nil), raw...), make([]byte, MaxPlaintextBytes)...)),
		"first byte not 0x04":    encode(compressed),
		"point not on the curve": encode(offCurve),
		"a public key":           v.Public,
	}
	for why, value := range bad {
		if err := CheckSealed(value); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: CheckSealed = %v, want ErrMalformed", why, err)
		}
	}
	if !strings.ContainsAny(body, "-_") {
		t.Fatal("the vector has no URL-safe character: the standard-alphabet case proves nothing")
	}
	if err := CheckSealed(good); err != nil {
		t.Fatalf("the vector is refused: %v", err)
	}
}

func TestValidName(t *testing.T) {
	good := []string{"x", "nas.docs.password", "ai.answer.api_key", "backup.s3.secret_key", "plugin.a-b.c_d",
		"a" + strings.Repeat("9", 62)}
	bad := []string{"", "X", "Nas.docs", "9x", ".x", "-x", "_x", "a b", "a/b", "a\\b", "a\n", "a\x00", "é",
		"a" + strings.Repeat("9", 63)}
	for _, name := range good {
		if !ValidName(name) {
			t.Errorf("%q must be valid", name)
		}
	}
	for _, name := range bad {
		if ValidName(name) {
			t.Errorf("%q must be invalid", name)
		}
	}
	if len(good[len(good)-1]) != MaxNameLen {
		t.Fatal("MaxNameLen does not match the pattern")
	}
}

func TestErrorsCarryNoSecretMaterial(t *testing.T) {
	v, key := loadVectors(t)
	other := mustGenerate(t)
	plaintext := []byte("correct horse battery staple")
	sealed, err := Seal(key.Public(), "nas.docs.password", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	var messages []string
	collect := func(err error) {
		if err == nil {
			t.Fatal("expected an error")
		}
		messages = append(messages, err.Error())
	}
	_, err = other.Open("nas.docs.password", sealed)
	collect(err)
	_, err = key.Open("nas.other.password", sealed)
	collect(err)
	_, err = key.Open("nas.docs.password", sealed[:len(sealed)-3])
	collect(err)
	collect(CheckSealed("hunter2-in-clear-text"))
	_, err = Seal("hmk1.secret-looking-input", "x", plaintext)
	collect(err)
	_, err = Seal(key.Public(), "x", make([]byte, MaxPlaintextBytes+1))
	collect(err)

	for _, msg := range messages {
		for _, leak := range []string{string(plaintext), sealed, sealed[len(SealedPrefix) : len(SealedPrefix)+16],
			"hunter2", "secret-looking", v.ScalarHex, v.PKCS8B64[:24]} {
			if strings.Contains(msg, leak) {
				t.Errorf("error %q contains %q", msg, leak)
			}
		}
	}
}

func TestPrivateKeyNeverPrints(t *testing.T) {
	v, key := loadVectors(t)
	scalar, _ := hex.DecodeString(v.ScalarHex)
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%q", "%d"} {
		for _, value := range []any{key, *key} {
			out := fmt.Sprintf(format, value)
			if out != "seal.PrivateKey(redacted)" {
				t.Errorf("%s prints %q", format, out)
			}
			if strings.Contains(strings.ToLower(out), v.ScalarHex) || strings.Contains(out, fmt.Sprint(scalar)) {
				t.Errorf("%s prints the private scalar", format)
			}
		}
	}
	if data, err := json.Marshal(key); err != nil || string(data) != "{}" {
		t.Errorf("JSON encoding of a private key = %s, %v", data, err)
	}
}

func TestWipe(t *testing.T) {
	b := []byte("secret")
	Wipe(b)
	if !bytes.Equal(b, make([]byte, 6)) {
		t.Fatalf("not wiped: %v", b)
	}
	Wipe(nil)
}

// --- the key file ------------------------------------------------------------

func TestLoadOrCreateCreatesOnceWithMode0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seal.key")
	key, err := LoadOrCreateOwnedBy(path, myUID())
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want a regular file with 0600", fi.Mode())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "-----BEGIN PRIVATE KEY-----\n") || !strings.HasSuffix(string(data), "-----END PRIVATE KEY-----\n") {
		t.Fatalf("the key file is not a PKCS #8 PEM block")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}

	// The second call loads the same key and does not rewrite the file.
	again, err := LoadOrCreateOwnedBy(path, myUID())
	if err != nil {
		t.Fatal(err)
	}
	if again.Public() != key.Public() {
		t.Fatal("LoadOrCreate replaced an existing key")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, data) {
		t.Fatal("LoadOrCreate rewrote the key file")
	}
	loaded, err := LoadOwnedBy(path, myUID())
	if err != nil {
		t.Fatal(err)
	}
	// The loaded key opens what was sealed for the created one.
	sealed, _ := Seal(key.Public(), "x", []byte("s3cret"))
	if got, err := loaded.Open("x", sealed); err != nil || string(got) != "s3cret" {
		t.Fatalf("the reloaded key does not open: %q, %v", got, err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := LoadOwnedBy(filepath.Join(t.TempDir(), "seal.key"), myUID())
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want fs.ErrNotExist", err)
	}
	// A missing directory is not created.
	if _, err := LoadOrCreateOwnedBy(filepath.Join(t.TempDir(), "missing", "seal.key"), myUID()); err == nil {
		t.Fatal("expected an error for a missing directory")
	}
}

func TestProductionEntryPointsRequireRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seal.key")
	if os.Geteuid() == RootUID {
		key, err := LoadOrCreate(path)
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := Load(path)
		if err != nil || loaded.Public() != key.Public() {
			t.Fatalf("Load after LoadOrCreate: %v", err)
		}
		return
	}
	if _, err := LoadOrCreate(path); err == nil {
		t.Fatal("LoadOrCreate must refuse to create the key as a non-root user")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("a refused creation left files behind: %v", entries)
	}
	if _, err := LoadOrCreateOwnedBy(path, myUID()); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load must refuse a key that root does not own")
	}
}

func TestCreationNeedsTheOwnerUID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seal.key")
	if _, err := LoadOrCreateOwnedBy(path, myUID()+1); err == nil {
		t.Fatal("creating a key for another uid must fail")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("a refused creation left files behind: %v", entries)
	}
}

func TestKeyFileMustBeTrustworthy(t *testing.T) {
	newKeyFile := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "seal.key")
		if _, err := LoadOrCreateOwnedBy(path, myUID()); err != nil {
			t.Fatal(err)
		}
		return path
	}
	// refused checks both entry points and that the file was left alone.
	refused := func(t *testing.T, path, why string) {
		t.Helper()
		before, _ := os.ReadFile(path)
		if _, err := LoadOwnedBy(path, myUID()); err == nil {
			t.Fatalf("Load: %s must be refused", why)
		} else if errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Load: %s reported as a missing file: %v", why, err)
		}
		if _, err := LoadOrCreateOwnedBy(path, myUID()); err == nil {
			t.Fatalf("LoadOrCreate: %s must be refused", why)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatalf("LoadOrCreate changed the file although %s", why)
		}
	}

	for _, mode := range []os.FileMode{0o640, 0o604, 0o620, 0o602, 0o660, 0o644, 0o666, 0o610, 0o601} {
		path := newKeyFile(t)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		refused(t, path, fmt.Sprintf("mode %04o", mode))
	}

	t.Run("another owner", func(t *testing.T) {
		path := newKeyFile(t)
		if _, err := LoadOwnedBy(path, myUID()+1); err == nil {
			t.Fatal("a key owned by someone else must be refused")
		}
		if _, err := LoadOrCreateOwnedBy(path, myUID()+1); err == nil {
			t.Fatal("a key owned by someone else must be refused")
		}
	})

	t.Run("symbolic link", func(t *testing.T) {
		real := newKeyFile(t)
		link := filepath.Join(t.TempDir(), "seal.key")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		refused(t, link, "a symbolic link")
	})

	t.Run("dangling symbolic link", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "elsewhere")
		link := filepath.Join(dir, "seal.key")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreateOwnedBy(link, myUID()); err == nil {
			t.Fatal("a dangling symbolic link must be refused")
		}
		if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("the key was created through a symbolic link")
		}
	})

	t.Run("directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "seal.key")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		refused(t, path, "a directory")
		if _, err := LoadOwnedBy(path, myUID()); err == nil || !strings.Contains(err.Error(), "is not a regular file") {
			t.Fatalf("a directory is refused for another reason: %v", err)
		}
	})

	t.Run("fifo", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "seal.key")
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Skipf("mkfifo: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := LoadOrCreateOwnedBy(path, myUID())
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("a FIFO must be refused")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("loading hangs on a FIFO")
		}
	})

	t.Run("content", func(t *testing.T) {
		good, _ := os.ReadFile(newKeyFile(t))
		for why, content := range map[string][]byte{
			"empty":              {},
			"garbage":            []byte("not-a-key-but-very-private-looking\n"),
			"two blocks":         append(append([]byte(nil), good...), good...),
			"trailing text":      append(append([]byte(nil), good...), []byte("extra")...),
			"wrong block type":   bytes.ReplaceAll(good, []byte("PRIVATE KEY"), []byte("EC PRIVATE KEY")),
			"truncated":          good[:len(good)/2],
			"too large":          bytes.Repeat([]byte("A"), maxKeyFileBytes+1),
			"public key instead": []byte("hmk1.BHqMZ5y0R-ZqUgMyQnIG7COJHRBudGlPYXahXnAanVs0zizDQPwx0RPbBK5G3lOWd579QDu7xuOJaLJ7qLrnZt0\n"),
		} {
			path := filepath.Join(t.TempDir(), "seal.key")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadOwnedBy(path, myUID())
			if err == nil {
				t.Errorf("%s: must be refused", why)
				continue
			}
			if len(content) > 8 && strings.Contains(err.Error(), string(content[:8])) {
				t.Errorf("%s: the error quotes the file: %v", why, err)
			}
			// An unusable file is never replaced by a fresh key.
			if _, err := LoadOrCreateOwnedBy(path, myUID()); err == nil {
				t.Errorf("%s: LoadOrCreate must not replace an unusable file", why)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(after, content) {
				t.Errorf("%s: the file was changed", why)
			}
		}
	})
}

func TestKeyFileOfAnotherCurveIsRefused(t *testing.T) {
	// A valid PKCS #8 key that is not P-256 must not load.
	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for why, key := range map[string]any{"x25519": x25519Key, "p384": p384Key} {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "seal.key")
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOwnedBy(path, myUID()); err == nil {
			t.Errorf("%s: must be refused", why)
		}
	}
}

func TestTrailingNewlinesAfterThePEMBlockAreAccepted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seal.key")
	key, err := LoadOrCreateOwnedBy(path, myUID())
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(data, '\n', '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadOwnedBy(path, myUID())
	if err != nil || loaded.Public() != key.Public() {
		t.Fatalf("a key file edited to end with blank lines: %v", err)
	}
}

func TestCreateExclusiveNeverReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seal.key")
	if err := createExclusive(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	// A second creation, as after a lost race, fails and leaves the file.
	err := createExclusive(path, []byte("second"))
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("err = %v, want fs.ErrExist", err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "first" {
		t.Fatalf("the existing file was replaced: %q", data)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
	// Whatever is in the way is left alone: a directory, a dangling link.
	for _, obstacle := range []func(string) error{
		func(p string) error { return os.Mkdir(p, 0o700) },
		func(p string) error { return os.Symlink(filepath.Join(dir, "nowhere"), p) },
	} {
		blocked := filepath.Join(t.TempDir(), "seal.key")
		if err := obstacle(blocked); err != nil {
			t.Fatal(err)
		}
		if err := createExclusive(blocked, []byte("x")); !errors.Is(err, fs.ErrExist) {
			t.Fatalf("err = %v, want fs.ErrExist", err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "nowhere")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a file was created through a symbolic link")
	}
}
