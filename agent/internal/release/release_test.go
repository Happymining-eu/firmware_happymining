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
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// vectorPath is the file shared with the Python implementation.
const vectorPath = "../../../appliance/testdata/release-vector.json"

type vector struct {
	Seed      []byte
	Public    ed25519.PublicKey
	PublicB64 string
	KeyID     string
	Manifest  []byte
	Signature string
	Artifact  []byte
}

func loadVector(t *testing.T) vector {
	t.Helper()
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Seed      string `json:"private_seed_b64"`
		Public    string `json:"public_key_b64"`
		KeyID     string `json:"key_id"`
		Manifest  string `json:"manifest_b64"`
		Signature string `json:"signature_b64"`
		Artifact  string `json:"artifact_b64"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	v := vector{
		Seed: decode(raw.Seed), Public: decode(raw.Public), PublicB64: raw.Public, KeyID: raw.KeyID,
		Manifest: decode(raw.Manifest), Signature: raw.Signature, Artifact: decode(raw.Artifact),
	}
	if len(v.Seed) != ed25519.SeedSize || len(v.Public) != ed25519.PublicKeySize {
		t.Fatal("the vector's key has the wrong size")
	}
	return v
}

func (v vector) keys() Keys { return Keys{KeyID(v.Public): v.Public} }

func myUID() uint32 { return uint32(os.Getuid()) }

// signer signs manifests with a key made for one test.
type signer struct {
	priv ed25519.PrivateKey
	keys Keys
}

func newSigner(t *testing.T) signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return signer{priv: priv, keys: Keys{KeyID(pub): pub}}
}

func (s signer) sign(manifest []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, manifest))
}

func (s signer) verify(manifest string) (*Manifest, error) {
	return Verify([]byte(manifest), s.sign([]byte(manifest)), s.keys)
}

const goodSHA = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" // SHA-256 of "hello world"

// manifestJSON builds a manifest; fields replaces or, with a nil value,
// removes top-level keys.
func manifestJSON(t *testing.T, fields map[string]any) string {
	t.Helper()
	doc := map[string]any{
		"schema":           1,
		"product":          "happymining-agent",
		"version":          "0.2.0",
		"created_at":       "2026-10-02T12:00:00Z",
		"artifact":         map[string]any{"filename": "happymining-agent_0.2.0_amd64.deb", "size": 11, "sha256": goodSHA},
		"min_upgrade_from": "0.1.0",
		"notes":            "Test release.",
	}
	for key, value := range fields {
		if value == nil {
			delete(doc, key)
		} else {
			doc[key] = value
		}
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestVectorVerifies(t *testing.T) {
	v := loadVector(t)
	if got := KeyID(v.Public); got != v.KeyID {
		t.Fatalf("KeyID = %s, want %s", got, v.KeyID)
	}
	if derived := ed25519.NewKeyFromSeed(v.Seed).Public().(ed25519.PublicKey); !bytes.Equal(derived, v.Public) {
		t.Fatal("the vector's seed and public key do not belong together")
	}
	m, err := Verify(v.Manifest, v.Signature, v.keys())
	if err != nil {
		t.Fatal(err)
	}
	want := Manifest{
		Version: "0.2.0", Filename: "happymining-agent_0.2.0_amd64.deb", Size: 11, SHA256: goodSHA,
		Notes: "Test release.", MinUpgradeFrom: "0.1.0", KeyID: v.KeyID, Raw: v.Manifest,
	}
	if m.Version != want.Version || m.Filename != want.Filename || m.Size != want.Size || m.SHA256 != want.SHA256 ||
		m.Notes != want.Notes || m.MinUpgradeFrom != want.MinUpgradeFrom || m.KeyID != want.KeyID || !bytes.Equal(m.Raw, want.Raw) {
		t.Fatalf("manifest = %+v", m)
	}
	// The vector's artifact is the package the manifest describes.
	path := filepath.Join(t.TempDir(), m.Filename)
	if err := os.WriteFile(path, v.Artifact, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckArtifact(path, m); err != nil {
		t.Fatal(err)
	}
	if err := CheckUpgrade("0.1.0", m); err != nil {
		t.Fatal(err)
	}
}

func TestAnyChangedByteOfTheManifestFails(t *testing.T) {
	v := loadVector(t)
	for i := range v.Manifest {
		mutated := append([]byte(nil), v.Manifest...)
		mutated[i] ^= 0x01
		if _, err := Verify(mutated, v.Signature, v.keys()); !errors.Is(err, ErrSignature) {
			t.Fatalf("byte %d flipped: err = %v, want ErrSignature", i, err)
		}
	}
	for _, mutated := range [][]byte{v.Manifest[:len(v.Manifest)-1], append(append([]byte(nil), v.Manifest...), '\n'), {}} {
		if _, err := Verify(mutated, v.Signature, v.keys()); !errors.Is(err, ErrSignature) {
			t.Fatalf("manifest of %d bytes: err = %v, want ErrSignature", len(mutated), err)
		}
	}
}

func TestAnyChangedByteOfTheSignatureFails(t *testing.T) {
	v := loadVector(t)
	signature, err := base64.StdEncoding.DecodeString(v.Signature)
	if err != nil {
		t.Fatal(err)
	}
	for i := range signature {
		mutated := append([]byte(nil), signature...)
		mutated[i] ^= 0x80
		if _, err := Verify(v.Manifest, base64.StdEncoding.EncodeToString(mutated), v.keys()); !errors.Is(err, ErrSignature) {
			t.Fatalf("signature byte %d flipped: err = %v, want ErrSignature", i, err)
		}
	}
	for why, bad := range map[string]string{
		"empty":             "",
		"not base64":        "!!!not base64!!!",
		"URL-safe alphabet": strings.NewReplacer("+", "-", "/", "_").Replace(v.Signature),
		"no padding":        strings.TrimRight(v.Signature, "="),
		"trailing newline":  v.Signature + "\n",
		"leading space":     " " + v.Signature,
		"truncated":         base64.StdEncoding.EncodeToString(signature[:63]),
		"too long":          base64.StdEncoding.EncodeToString(append(append([]byte(nil), signature...), 0)),
		"the public key":    v.PublicB64,
	} {
		if _, err := Verify(v.Manifest, bad, v.keys()); !errors.Is(err, ErrSignature) {
			t.Errorf("%s: err = %v, want ErrSignature", why, err)
		}
	}
}

func TestUnknownKeyAndNoKeysFail(t *testing.T) {
	v := loadVector(t)
	stranger := newSigner(t)
	if _, err := Verify(v.Manifest, v.Signature, stranger.keys); !errors.Is(err, ErrSignature) {
		t.Fatalf("a manifest signed by an unknown key: err = %v, want ErrSignature", err)
	}
	// A valid signature by a key that is not installed.
	manifest := manifestJSON(t, nil)
	if _, err := Verify([]byte(manifest), stranger.sign([]byte(manifest)), v.keys()); !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
	for _, keys := range []Keys{nil, {}} {
		if _, err := Verify(v.Manifest, v.Signature, keys); !errors.Is(err, ErrNoKeys) {
			t.Fatalf("no keys: err = %v, want ErrNoKeys", err)
		}
	}
	// A set with several keys verifies with the right one and names it.
	both := Keys{}
	for id, key := range stranger.keys {
		both[id] = key
	}
	both[v.KeyID] = v.Public
	m, err := Verify(v.Manifest, v.Signature, both)
	if err != nil || m.KeyID != v.KeyID {
		t.Fatalf("two keys installed: %v, %+v", err, m)
	}
	// A malformed entry in a hand-built set neither panics nor verifies.
	if _, err := Verify(v.Manifest, v.Signature, Keys{"short": ed25519.PublicKey("too short")}); !errors.Is(err, ErrSignature) {
		t.Fatalf("a key of the wrong size: err = %v", err)
	}
}

func TestSignedManifestContentIsValidated(t *testing.T) {
	s := newSigner(t)
	artifact := func(fields map[string]any) map[string]any {
		a := map[string]any{"filename": "happymining-agent_0.2.0_amd64.deb", "size": 11, "sha256": goodSHA}
		for key, value := range fields {
			if value == nil {
				delete(a, key)
			} else {
				a[key] = value
			}
		}
		return a
	}
	if _, err := s.verify(manifestJSON(t, nil)); err != nil {
		t.Fatalf("the base manifest must verify: %v", err)
	}

	bad := map[string]string{
		"schema 2":                  manifestJSON(t, map[string]any{"schema": 2}),
		"schema missing":            manifestJSON(t, map[string]any{"schema": nil}),
		"schema as a string":        manifestJSON(t, map[string]any{"schema": "1"}),
		"schema as a boolean":       manifestJSON(t, map[string]any{"schema": true}),
		"schema as a fraction":      strings.Replace(manifestJSON(t, nil), `"schema":1`, `"schema":1.0`, 1),
		"another product":           manifestJSON(t, map[string]any{"product": "happymining-api"}),
		"product missing":           manifestJSON(t, map[string]any{"product": nil}),
		"version with a v":          manifestJSON(t, map[string]any{"version": "v0.2.0"}),
		"version with two parts":    manifestJSON(t, map[string]any{"version": "0.2"}),
		"version as a number":       manifestJSON(t, map[string]any{"version": 2}),
		"version missing":           manifestJSON(t, map[string]any{"version": nil}),
		"min_upgrade_from bad":      manifestJSON(t, map[string]any{"min_upgrade_from": "latest"}),
		"min_upgrade_from number":   manifestJSON(t, map[string]any{"min_upgrade_from": 1}),
		"artifact missing":          manifestJSON(t, map[string]any{"artifact": nil}),
		"artifact not an object":    manifestJSON(t, map[string]any{"artifact": "x.deb"}),
		"filename missing":          manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"filename": nil})}),
		"filename with a directory": manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"filename": "../x.deb"})}),
		"filename absolute":         manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"filename": "/tmp/x.deb"})}),
		"filename hidden":           manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"filename": ".x.deb"})}),
		"filename as an option":     manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"filename": "-i.deb"})}),
		"filename not a .deb":       manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"filename": "x.rpm"})}),
		"filename with a space":     manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"filename": "x y.deb"})}),
		"filename with a newline":   manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"filename": "x.deb\n"})}),
		"filename too long":         manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"filename": strings.Repeat("a", 122) + ".deb"})}),
		"size zero":                 manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"size": 0})}),
		"size negative":             manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"size": -1})}),
		"size above 512 MiB":        manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"size": MaxArtifactBytes + 1})}),
		"size as a string":          manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"size": "11"})}),
		"size as a boolean":         manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"size": true})}),
		"size as a fraction":        manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"size": 11.5})}),
		"size with an exponent":     strings.Replace(manifestJSON(t, nil), `"size":11`, `"size":1e1`, 1),
		"size beyond int64":         strings.Replace(manifestJSON(t, nil), `"size":11`, `"size":99999999999999999999`, 1),
		"size missing":              manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"size": nil})}),
		"sha256 upper case":         manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"sha256": strings.ToUpper(goodSHA)})}),
		"sha256 short":              manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"sha256": goodSHA[:63]})}),
		"sha256 missing":            manifestJSON(t, map[string]any{"artifact": artifact(map[string]any{"sha256": nil})}),
		"not JSON":                  "schema: 1",
		"an array":                  "[1]",
		"null":                      "null",
		"two documents":             manifestJSON(t, nil) + manifestJSON(t, nil),
		"trailing text":             manifestJSON(t, nil) + " x",
		"not UTF-8":                 strings.Replace(manifestJSON(t, nil), "Test release.", "Test\xff", 1),
		"empty":                     "",
	}
	for why, manifest := range bad {
		if strings.Contains(why, "size with") || strings.Contains(why, "schema as a fraction") || strings.Contains(why, "size beyond") {
			if manifest == manifestJSON(t, nil) {
				t.Fatalf("%s: the replacement did not apply", why)
			}
		}
		if _, err := s.verify(manifest); !errors.Is(err, ErrManifest) {
			t.Errorf("%s: err = %v, want ErrManifest", why, err)
		}
	}

	// Too large is refused before anything else is looked at.
	huge := manifestJSON(t, map[string]any{"notes": strings.Repeat("n", MaxManifestBytes)})
	if _, err := s.verify(huge); !errors.Is(err, ErrManifest) {
		t.Errorf("a manifest above %d bytes: err = %v", MaxManifestBytes, err)
	}
}

func TestSignedManifestLeniencesOfTheReference(t *testing.T) {
	s := newSigner(t)
	// min_upgrade_from defaults to 0.0.0.
	m, err := s.verify(manifestJSON(t, map[string]any{"min_upgrade_from": nil}))
	if err != nil || m.MinUpgradeFrom != "0.0.0" {
		t.Fatalf("without min_upgrade_from: %v, %+v", err, m)
	}
	// Notes are optional, cut to 4000 characters (not bytes), and a value
	// that is not a string is not kept.
	m, err = s.verify(manifestJSON(t, map[string]any{"notes": nil}))
	if err != nil || m.Notes != "" {
		t.Fatalf("without notes: %v, %+v", err, m)
	}
	m, err = s.verify(manifestJSON(t, map[string]any{"notes": strings.Repeat("é", MaxNotesLen+50)}))
	if err != nil || m.Notes != strings.Repeat("é", MaxNotesLen) {
		t.Fatalf("long notes: %v, %d characters", err, len([]rune(m.Notes)))
	}
	m, err = s.verify(manifestJSON(t, map[string]any{"notes": 42}))
	if err != nil || m.Notes != "" {
		t.Fatalf("notes that are not a string: %v, %+v", err, m)
	}
	// Unknown keys are ignored, as in the reference.
	m, err = s.verify(manifestJSON(t, map[string]any{"future_field": map[string]any{"a": 1}}))
	if err != nil || m.Version != "0.2.0" {
		t.Fatalf("an unknown key: %v", err)
	}
	// White space around the object is part of the signed bytes and harmless.
	padded := "\n " + manifestJSON(t, nil) + "\n\n"
	m, err = s.verify(padded)
	if err != nil || string(m.Raw) != padded {
		t.Fatalf("white space around the manifest: %v", err)
	}
	// The largest size is accepted.
	if _, err := s.verify(manifestJSON(t, map[string]any{"artifact": map[string]any{
		"filename": "a.deb", "size": MaxArtifactBytes, "sha256": goodSHA}})); err != nil {
		t.Fatalf("a 512 MiB package: %v", err)
	}
}

func TestParseVersion(t *testing.T) {
	good := map[string]Version{
		"0.0.0":                {0, 0, 0},
		"0.2.0":                {0, 2, 0},
		"1.2.3":                {1, 2, 3},
		"10.20.30":             {10, 20, 30},
		"999999.999999.999999": {999999, 999999, 999999},
	}
	for text, want := range good {
		got, err := ParseVersion(text)
		if err != nil || got != want {
			t.Errorf("ParseVersion(%q) = %v, %v", text, got, err)
		}
		if got.String() != text {
			t.Errorf("String() of %q = %q", text, got.String())
		}
	}
	bad := []string{
		"", "1", "1.2", "1.2.3.4", "1.2.3.", ".1.2.3", "1..3", "01.2.3", "1.02.3", "1.2.03", "00.0.0",
		"-1.2.3", "1.-2.3", "1.2.-3", "+1.2.3", "1.2.3-rc1", "1.2.3+build", "v1.2.3", "1.2.x", "1.2.3 ", " 1.2.3",
		"1.2.3\n", "1,2,3", "1.2.1000000", "1000000.0.0", "1.99999999999999999999.3", "１.２.３", "1.2.3\x00",
	}
	for _, text := range bad {
		if v, err := ParseVersion(text); !errors.Is(err, ErrVersion) {
			t.Errorf("ParseVersion(%q) = %v, %v; want ErrVersion", text, v, err)
		}
	}
}

func TestVersionCompare(t *testing.T) {
	ordered := []string{"0.0.0", "0.0.1", "0.0.10", "0.1.0", "0.2.0", "0.10.0", "1.0.0", "1.0.9", "1.9.0", "2.0.0", "10.0.0"}
	for i, a := range ordered {
		for j, b := range ordered {
			va, _ := ParseVersion(a)
			vb, _ := ParseVersion(b)
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := va.Compare(vb); got != want {
				t.Errorf("%s compared to %s = %d, want %d", a, b, got, want)
			}
		}
	}
}

func TestCheckUpgrade(t *testing.T) {
	m := &Manifest{Version: "0.5.0", MinUpgradeFrom: "0.3.0"}
	for _, installed := range []string{"0.3.0", "0.3.1", "0.4.9", "0.4.999"} {
		if err := CheckUpgrade(installed, m); err != nil {
			t.Errorf("installed %s: %v", installed, err)
		}
	}
	refused := map[string]string{
		"equal version":              "0.5.0",
		"downgrade by patch":         "0.5.1",
		"downgrade by minor":         "0.6.0",
		"downgrade by major":         "1.0.0",
		"below min_upgrade_from":     "0.2.9",
		"far below min_upgrade_from": "0.0.1",
	}
	for why, installed := range refused {
		if err := CheckUpgrade(installed, m); !errors.Is(err, ErrNotAnUpgrade) {
			t.Errorf("%s (%s): err = %v, want ErrNotAnUpgrade", why, installed, err)
		}
	}
	// Numbers, not strings: 0.10.0 is newer than 0.9.0.
	if err := CheckUpgrade("0.9.0", &Manifest{Version: "0.10.0", MinUpgradeFrom: "0.0.0"}); err != nil {
		t.Errorf("0.9.0 to 0.10.0: %v", err)
	}
	if err := CheckUpgrade("0.10.0", &Manifest{Version: "0.9.0", MinUpgradeFrom: "0.0.0"}); !errors.Is(err, ErrNotAnUpgrade) {
		t.Errorf("0.10.0 to 0.9.0: err = %v", err)
	}
	for _, installed := range []string{"", "dev", "0.1", "0.1.0-dirty"} {
		if err := CheckUpgrade(installed, m); !errors.Is(err, ErrVersion) {
			t.Errorf("installed %q: err = %v, want ErrVersion", installed, err)
		}
	}
	if err := CheckUpgrade("0.1.0", nil); err == nil {
		t.Error("a nil manifest must be refused")
	}
	if err := CheckUpgrade("0.1.0", &Manifest{Version: "x", MinUpgradeFrom: "0.0.0"}); err == nil {
		t.Error("a manifest that Verify did not produce must be refused")
	}
}

func artifactManifest(content []byte) *Manifest {
	sum := sha256.Sum256(content)
	return &Manifest{Version: "0.2.0", Filename: "happymining-agent_0.2.0_amd64.deb", Size: int64(len(content)),
		SHA256: hex.EncodeToString(sum[:]), MinUpgradeFrom: "0.0.0"}
}

func TestCheckArtifact(t *testing.T) {
	content := []byte("hello world")
	m := artifactManifest(content)
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	good := write("good.deb", content)
	if err := CheckArtifact(good, m); err != nil {
		t.Fatal(err)
	}
	for why, path := range map[string]string{
		"one byte changed": write("changed.deb", []byte("hello World")),
		"one byte short":   write("short.deb", content[:len(content)-1]),
		"one byte long":    write("long.deb", append(append([]byte(nil), content...), '!')),
		"empty":            write("empty.deb", nil),
	} {
		if err := CheckArtifact(path, m); !errors.Is(err, ErrArtifact) {
			t.Errorf("%s: err = %v, want ErrArtifact", why, err)
		}
	}
	// Right size, wrong hash recorded in the manifest.
	wrongHash := *m
	wrongHash.SHA256 = strings.Repeat("0", 64)
	if err := CheckArtifact(good, &wrongHash); !errors.Is(err, ErrArtifact) {
		t.Errorf("hash mismatch: err = %v, want ErrArtifact", err)
	}
	wrongSize := *m
	wrongSize.Size++
	if err := CheckArtifact(good, &wrongSize); !errors.Is(err, ErrArtifact) {
		t.Errorf("size mismatch: err = %v, want ErrArtifact", err)
	}

	link := filepath.Join(dir, "link.deb")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckArtifact(link, m); err == nil {
		t.Error("a symbolic link to the right package must be refused")
	}
	if err := CheckArtifact(dir, m); err == nil {
		t.Error("a directory must be refused")
	}
	if err := CheckArtifact(filepath.Join(dir, "missing.deb"), m); err == nil {
		t.Error("a missing file must be refused")
	}
	fifo := filepath.Join(dir, "fifo.deb")
	if err := syscall.Mkfifo(fifo, 0o644); err == nil {
		done := make(chan error, 1)
		go func() { done <- CheckArtifact(fifo, m) }()
		select {
		case err := <-done:
			if err == nil {
				t.Error("a FIFO must be refused")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("CheckArtifact hangs on a FIFO")
		}
	}
	if err := CheckArtifact(good, nil); err == nil {
		t.Error("a nil manifest must be refused")
	}
	if err := CheckArtifact(good, &Manifest{Filename: "../x.deb", Size: m.Size, SHA256: m.SHA256}); err == nil {
		t.Error("a manifest that Verify did not produce must be refused")
	}
}

func TestStageArtifact(t *testing.T) {
	content := bytes.Repeat([]byte("package bytes "), 5000)
	m := artifactManifest(content)
	srcDir, dstDir := t.TempDir(), t.TempDir()
	src := filepath.Join(srcDir, "download.part")
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}
	staged, err := StageArtifact(src, dstDir, m)
	if err != nil {
		t.Fatal(err)
	}
	if staged != filepath.Join(dstDir, m.Filename) {
		t.Fatalf("staged at %s", staged)
	}
	fi, err := os.Lstat(staged)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("staged file: %v, %v", fi, err)
	}
	got, _ := os.ReadFile(staged)
	if !bytes.Equal(got, content) {
		t.Fatal("the staged copy differs from the source")
	}
	if err := CheckArtifact(staged, m); err != nil {
		t.Fatal(err)
	}
	// Changing the source afterwards does not change what was staged.
	if err := os.WriteFile(src, []byte("swapped"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckArtifact(staged, m); err != nil {
		t.Fatalf("the staged copy followed the source: %v", err)
	}
	// Staging again replaces the earlier copy.
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := StageArtifact(src, dstDir, m); err != nil {
		t.Fatal(err)
	}

	// A package that does not match leaves nothing behind.
	empty := t.TempDir()
	tampered := append([]byte(nil), content...)
	tampered[100] ^= 1
	for why, data := range map[string][]byte{"tampered": tampered, "truncated": content[:len(content)-1]} {
		if err := os.WriteFile(src, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := StageArtifact(src, empty, m); !errors.Is(err, ErrArtifact) {
			t.Errorf("%s: err = %v, want ErrArtifact", why, err)
		}
		if entries, _ := os.ReadDir(empty); len(entries) != 0 {
			t.Errorf("%s: files left behind: %v", why, entries)
		}
	}
	link := filepath.Join(srcDir, "link")
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(src, link); err != nil {
		t.Fatal(err)
	}
	if _, err := StageArtifact(link, empty, m); err == nil {
		t.Error("a symbolic link must be refused")
	}
	if _, err := StageArtifact(src, filepath.Join(empty, "missing"), m); err == nil {
		t.Error("a missing destination directory must be refused")
	}
	if entries, _ := os.ReadDir(empty); len(entries) != 0 {
		t.Errorf("files left behind: %v", entries)
	}
}

func TestParsePublicKey(t *testing.T) {
	v := loadVector(t)
	key, err := ParsePublicKey(v.PublicB64)
	if err != nil || !bytes.Equal(key, v.Public) {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	for why, bad := range map[string]string{
		"empty":            "",
		"31 bytes":         base64.StdEncoding.EncodeToString(v.Public[:31]),
		"33 bytes":         base64.StdEncoding.EncodeToString(append(append([]byte(nil), v.Public...), 0)),
		"no padding":       strings.TrimRight(v.PublicB64, "="),
		"URL-safe":         base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32)),
		"trailing newline": v.PublicB64 + "\n",
		"space":            v.PublicB64[:10] + " " + v.PublicB64[10:],
		"hex":              hex.EncodeToString(v.Public),
	} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("%s: must be refused", why)
		}
	}
}

func TestLoadKeys(t *testing.T) {
	v := loadVector(t)
	other := newSigner(t)
	var otherB64 string
	for _, key := range other.keys {
		otherB64 = base64.StdEncoding.EncodeToString(key)
	}
	newDir := func(t *testing.T, files map[string]string) string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "release-keys")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}

	t.Run("missing and empty directories yield no keys", func(t *testing.T) {
		for _, dir := range []string{filepath.Join(t.TempDir(), "missing"), newDir(t, nil), newDir(t, map[string]string{"README": "no keys here"})} {
			keys, err := LoadKeysOwnedBy(dir, myUID())
			if err != nil || len(keys) != 0 {
				t.Fatalf("%s: %v, %v", dir, keys, err)
			}
			if _, err := Verify(v.Manifest, v.Signature, keys); !errors.Is(err, ErrNoKeys) {
				t.Fatalf("Verify with no keys: %v", err)
			}
		}
	})

	t.Run("keys with and without a newline", func(t *testing.T) {
		dir := newDir(t, map[string]string{
			"test.pub":   v.PublicB64 + "\n",
			"second.pub": otherB64,
			"notes.txt":  "ignored",
			"old.pub~":   "ignored too",
		})
		keys, err := LoadKeysOwnedBy(dir, myUID())
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) != 2 || !bytes.Equal(keys[v.KeyID], v.Public) {
			t.Fatalf("keys = %v", keys)
		}
		if m, err := Verify(v.Manifest, v.Signature, keys); err != nil || m.KeyID != v.KeyID {
			t.Fatalf("Verify with loaded keys: %v", err)
		}
	})

	t.Run("anything wrong refuses the whole set", func(t *testing.T) {
		good := map[string]string{"good.pub": v.PublicB64 + "\n"}
		with := func(name, content string) map[string]string {
			return map[string]string{"good.pub": good["good.pub"], name: content}
		}
		for why, files := range map[string]map[string]string{
			"garbage":           with("bad.pub", "not a key\n"),
			"empty file":        with("bad.pub", ""),
			"two newlines":      with("bad.pub", v.PublicB64+"\n\n"),
			"CRLF":              with("bad.pub", v.PublicB64+"\r\n"),
			"leading space":     with("bad.pub", " "+v.PublicB64+"\n"),
			"two keys":          with("bad.pub", v.PublicB64+"\n"+otherB64+"\n"),
			"short key":         with("bad.pub", base64.StdEncoding.EncodeToString(v.Public[:16])+"\n"),
			"PEM":               with("bad.pub", "-----BEGIN PUBLIC KEY-----\n"+v.PublicB64+"\n-----END PUBLIC KEY-----\n"),
			"oversized":         with("bad.pub", strings.Repeat("A", maxKeyFileBytes+1)),
			"hidden .pub file":  with(".pub", "junk"),
			"private seed file": with("seed.pub", base64.StdEncoding.EncodeToString(append(append([]byte(nil), v.Seed...), v.Public...))),
		} {
			dir := newDir(t, files)
			if keys, err := LoadKeysOwnedBy(dir, myUID()); err == nil {
				t.Errorf("%s: loaded %d keys, must be refused", why, len(keys))
			}
		}
	})

	t.Run("permissions and ownership", func(t *testing.T) {
		files := map[string]string{"good.pub": v.PublicB64 + "\n"}
		for _, mode := range []os.FileMode{0o664, 0o646, 0o666} {
			dir := newDir(t, files)
			if err := os.Chmod(filepath.Join(dir, "good.pub"), mode); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadKeysOwnedBy(dir, myUID()); err == nil {
				t.Errorf("a key file with mode %04o must be refused", mode)
			}
		}
		for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
			dir := newDir(t, files)
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadKeysOwnedBy(dir, myUID()); err == nil {
				t.Errorf("a key directory with mode %04o must be refused", mode)
			}
		}
		dir := newDir(t, files)
		if _, err := LoadKeysOwnedBy(dir, myUID()+1); err == nil {
			t.Error("keys owned by someone else must be refused")
		}
		// Read-only modes are fine.
		if err := os.Chmod(filepath.Join(dir, "good.pub"), 0o444); err != nil {
			t.Fatal(err)
		}
		if keys, err := LoadKeysOwnedBy(dir, myUID()); err != nil || len(keys) != 1 {
			t.Errorf("a read-only key file: %v", err)
		}
	})

	t.Run("symbolic links and other file types", func(t *testing.T) {
		real := newDir(t, map[string]string{"good.pub": v.PublicB64 + "\n"})

		dir := newDir(t, nil)
		if err := os.Symlink(filepath.Join(real, "good.pub"), filepath.Join(dir, "link.pub")); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKeysOwnedBy(dir, myUID()); err == nil {
			t.Error("a symbolic link to a key must be refused")
		}

		linkDir := filepath.Join(t.TempDir(), "release-keys")
		if err := os.Symlink(real, linkDir); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKeysOwnedBy(linkDir, myUID()); err == nil {
			t.Error("a symbolic link in place of the key directory must be refused")
		}

		dir = newDir(t, nil)
		if err := os.Mkdir(filepath.Join(dir, "sub.pub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKeysOwnedBy(dir, myUID()); err == nil {
			t.Error("a directory named like a key must be refused")
		}

		file := filepath.Join(t.TempDir(), "release-keys")
		if err := os.WriteFile(file, []byte(v.PublicB64), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKeysOwnedBy(file, myUID()); err == nil {
			t.Error("a file in place of the key directory must be refused")
		}

		dir = newDir(t, nil)
		if err := syscall.Mkfifo(filepath.Join(dir, "fifo.pub"), 0o644); err == nil {
			done := make(chan error, 1)
			go func() {
				_, err := LoadKeysOwnedBy(dir, myUID())
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Error("a FIFO named like a key must be refused")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("LoadKeys hangs on a FIFO")
			}
		}
	})

	t.Run("too many key files", func(t *testing.T) {
		files := map[string]string{}
		for i := 0; i <= maxKeyFiles; i++ {
			files[fmt.Sprintf("k%02d.pub", i)] = v.PublicB64 + "\n"
		}
		if _, err := LoadKeysOwnedBy(newDir(t, files), myUID()); err == nil {
			t.Error("more key files than the bound must be refused")
		}
	})

	t.Run("production entry point insists on root", func(t *testing.T) {
		dir := newDir(t, map[string]string{"good.pub": v.PublicB64 + "\n"})
		keys, err := LoadKeys(dir)
		if os.Geteuid() == RootUID {
			if err != nil || len(keys) != 1 {
				t.Fatalf("as root: %v", err)
			}
		} else if err == nil {
			t.Fatal("keys that root does not own must be refused")
		}
	})
}
