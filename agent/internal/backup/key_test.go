package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
)

// testKey is the key of the fixed vectors: bytes 0x00..0x1f.
func testKey() Key {
	var k Key
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func mustNewKey(t *testing.T) Key {
	t.Helper()
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestNewKeyIsRandomAndNotZero(t *testing.T) {
	a, b := mustNewKey(t), mustNewKey(t)
	if a == b {
		t.Fatal("two new keys are equal")
	}
	if a.IsZero() || !(Key{}).IsZero() {
		t.Fatal("IsZero is wrong")
	}
}

func TestKeyIDIsFirstEightHexOfSHA256(t *testing.T) {
	k := testKey()
	sum := sha256.Sum256(k[:])
	want := hex.EncodeToString(sum[:])[:8]
	if got := KeyID(k); got != want || got != "630dcd29" {
		t.Fatalf("KeyID = %q, want %q (630dcd29 computed independently)", got, want)
	}
	// The header field is the first 8 bytes of the same hash.
	tag := keyTag(k)
	if hex.EncodeToString(tag[:]) != hex.EncodeToString(sum[:8]) || !strings.HasPrefix(hex.EncodeToString(tag[:]), KeyID(k)) {
		t.Fatalf("key tag %x", tag)
	}
}

func TestKeyNeverPrintsOrMarshals(t *testing.T) {
	k := testKey()
	secretHex := hex.EncodeToString(k[:])
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%d", "%q", "%o", "%b", "%c", "%U"} {
		for _, v := range []any{k, &k, struct{ K Key }{k}, []Key{k}} {
			out := fmt.Sprintf(verb, v)
			if strings.Contains(strings.ToLower(out), secretHex) || strings.Contains(out, "0 1 2 3") ||
				strings.Contains(out, "[0, 1, 2") || strings.Contains(out, "0x0, 0x1, 0x2") {
				t.Errorf("%s of %T leaks the key: %s", verb, v, out)
			}
			if !strings.Contains(out, "redacted") {
				t.Errorf("%s of %T = %q, want a redaction", verb, v, out)
			}
		}
	}
	if _, err := json.Marshal(k); err == nil {
		t.Error("a key was marshalled to JSON")
	}
	if _, err := json.Marshal(struct{ K Key }{k}); err == nil {
		t.Error("a struct with a key was marshalled to JSON")
	}
}

// reRecovery is the contract's shape: hmrk1- then groups of four base32
// characters, lower case, separated by "-" (the last group has three).
var reRecovery = regexp.MustCompile(`^hmrk1(-[a-z2-7]{4}){13}-[a-z2-7]{3}$`)

func TestRecoveryKeyRoundTripAndShape(t *testing.T) {
	// Computed with an independent implementation (Python base64.b32encode).
	const want = "hmrk1-aaaq-eaye-auda-ocaj-bifq-ydio-b4ib-ceqt-cqkr-mfyy-denb-wha5-dypw-gdi"
	if got := FormatRecoveryKey(testKey()); got != want {
		t.Fatalf("FormatRecoveryKey = %q, want %q", got, want)
	}
	for i := 0; i < 200; i++ {
		k := mustNewKey(t)
		text := FormatRecoveryKey(k)
		if !reRecovery.MatchString(text) {
			t.Fatalf("shape: %q", text)
		}
		back, err := ParseRecoveryKey(text)
		if err != nil || back != k {
			t.Fatalf("round trip failed: %v", err)
		}
	}
}

func TestParseRecoveryKeyIsTolerant(t *testing.T) {
	k := testKey()
	text := FormatRecoveryKey(k)
	body := strings.ReplaceAll(strings.TrimPrefix(text, "hmrk1-"), "-", "")
	variants := map[string]string{
		"upper case":         strings.ToUpper(text),
		"no dashes":          "hmrk1" + body,
		"spaces for dashes":  strings.ReplaceAll(text, "-", " "),
		"extra dashes":       strings.ReplaceAll(text, "-", "--"),
		"surrounding space":  "  \t" + text + " \r\n",
		"line break inside":  text[:30] + "\n" + text[30:],
		"groups of eight":    "HMRK1 " + body[:8] + " " + body[8:16] + "-" + body[16:],
		"typographic dashes": strings.ReplaceAll(text, "-", "–"),
		"mixed case":         strings.ToUpper(text[:20]) + text[20:],
	}
	for name, v := range variants {
		got, err := ParseRecoveryKey(v)
		if err != nil || got != k {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseRecoveryKeyDetectsEveryTypo(t *testing.T) {
	k := testKey()
	text := FormatRecoveryKey(k)
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	bytesText := []byte(text)
	accepted, tried := 0, 0
	for i := len("hmrk1-"); i < len(bytesText); i++ {
		if bytesText[i] == '-' {
			continue
		}
		for _, c := range []byte(alphabet) {
			if c == bytesText[i] {
				continue
			}
			typo := append([]byte(nil), bytesText...)
			typo[i] = c
			tried++
			got, err := ParseRecoveryKey(string(typo))
			if err == nil {
				accepted++
				if got == k {
					t.Fatalf("a different text gave the same key: %s", typo)
				}
				continue
			}
			if !errors.Is(err, ErrRecoveryKeyCheck) && !errors.Is(err, ErrRecoveryKeyFormat) {
				t.Fatalf("unexpected error %v", err)
			}
			if strings.Contains(err.Error(), string(typo[6:])) || strings.Contains(err.Error(), "aaaq") {
				t.Fatalf("the error repeats the key text: %v", err)
			}
		}
	}
	// A 16-bit check lets one wrong text in 65536 through; none of the
	// single-character typos of this key may pass.
	if accepted != 0 {
		t.Fatalf("%d of %d single-character typos were accepted", accepted, tried)
	}
	// Two characters swapped.
	swapped := []byte(text)
	swapped[6], swapped[7] = swapped[7], swapped[6]
	if string(swapped) != text {
		if _, err := ParseRecoveryKey(string(swapped)); !errors.Is(err, ErrRecoveryKeyCheck) {
			t.Fatalf("swap: %v", err)
		}
	}
}

func TestParseRecoveryKeyRefusesOtherShapes(t *testing.T) {
	text := FormatRecoveryKey(testKey())
	// The last character carries 2 key bits and 3 spare bits: "i" is 8
	// (01000); "j" (01001) has a spare bit set and is not a canonical text.
	nonCanonical := text[:len(text)-1] + "j"
	for name, v := range map[string]string{
		"empty":           "",
		"prefix only":     "hmrk1-",
		"wrong prefix":    "hmrk2" + text[5:],
		"no prefix":       text[6:],
		"too short":       text[:len(text)-1],
		"too long":        text + "a",
		"not base32":      text[:7] + "1" + text[8:],
		"not base32 (0)":  text[:7] + "0" + text[8:],
		"spare bits set":  nonCanonical,
		"very long":       strings.Repeat("a", 10000),
		"other separator": strings.ReplaceAll(text, "-", "_"),
		"hex":             hex.EncodeToString(make([]byte, 32)),
	} {
		if _, err := ParseRecoveryKey(v); !errors.Is(err, ErrRecoveryKeyFormat) {
			t.Errorf("%s: got %v, want ErrRecoveryKeyFormat", name, err)
		}
	}
}

func TestSaveAndLoadKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "backup.key")
	uid := uint32(os.Getuid())
	if _, err := LoadKey(path, uid); !errors.Is(err, ErrNoKey) {
		t.Fatalf("missing file: %v", err)
	}
	k := mustNewKey(t)
	// A permissive umask must not widen the file.
	old := syscall.Umask(0)
	err := SaveKey(path, k)
	syscall.Umask(old)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode() != 0o600 {
		t.Fatalf("mode %v, %v", fi.Mode(), err)
	}
	got, err := LoadKey(path, uid)
	if err != nil || got != k {
		t.Fatalf("LoadKey: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
	// The file is the recovery key text, so a damaged file is detected.
	data, _ := os.ReadFile(path)
	if string(data) != FormatRecoveryKey(k)+"\n" {
		t.Fatalf("unexpected key file content")
	}
}

func TestSaveKeyNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "backup.key")
	first, second := mustNewKey(t), mustNewKey(t)
	if err := SaveKey(path, first); err != nil {
		t.Fatal(err)
	}
	if err := SaveKey(path, second); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("second SaveKey: %v", err)
	}
	if got, err := LoadKey(path, uint32(os.Getuid())); err != nil || got != first {
		t.Fatalf("the first key was replaced: %v", err)
	}

	// A symbolic link at the path is "something there": not followed, not
	// replaced, and the link's target is not written.
	target := filepath.Join(dir, "elsewhere")
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := SaveKey(link, second); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("SaveKey over a dangling link: %v", err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("SaveKey wrote through the link: %v", err)
	}

	if err := SaveKey(filepath.Join(dir, "zero.key"), Key{}); !errors.Is(err, ErrZeroKey) {
		t.Fatalf("zero key: %v", err)
	}
	if err := SaveKey(filepath.Join(dir, "missing", "k"), first); err == nil {
		t.Fatal("expected an error for a missing directory")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestLoadKeyRefusesUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	uid := uint32(os.Getuid())
	k := mustNewKey(t)
	good := filepath.Join(dir, "good.key")
	if err := SaveKey(good, k); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(link, uid); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("symlink: %v", err)
	}

	for _, mode := range []os.FileMode{0o640, 0o604, 0o660, 0o644, 0o620, 0o601} {
		p := filepath.Join(dir, fmt.Sprintf("mode-%o.key", mode))
		if err := os.WriteFile(p, []byte(FormatRecoveryKey(k)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKey(p, uid); err == nil || !strings.Contains(err.Error(), "group or others") {
			t.Errorf("mode %o: %v", mode, err)
		}
	}

	if _, err := LoadKey(good, uid+1); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Errorf("wrong owner: %v", err)
	}
	if _, err := LoadKey(dir, uid); err == nil {
		t.Error("a directory was accepted")
	}

	fifo := filepath.Join(dir, "fifo.key")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(fifo, uid); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Errorf("fifo: %v", err)
	}

	damaged := filepath.Join(dir, "damaged.key")
	text := []byte(FormatRecoveryKey(k) + "\n")
	if text[10] == 'a' {
		text[10] = 'b'
	} else {
		text[10] = 'a'
	}
	if err := os.WriteFile(damaged, text, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadKey(damaged, uid)
	if !errors.Is(err, ErrRecoveryKeyCheck) && !errors.Is(err, ErrRecoveryKeyFormat) {
		t.Errorf("damaged: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), string(text[6:20])) {
		t.Errorf("the error repeats the file content: %v", err)
	}

	huge := filepath.Join(dir, "huge.key")
	if err := os.WriteFile(huge, []byte(strings.Repeat("a", 4096)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(huge, uid); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("huge: %v", err)
	}
}
