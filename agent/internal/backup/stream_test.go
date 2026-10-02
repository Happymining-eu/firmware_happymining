package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
)

// --- an independent implementation of the format, for the tests -------------
//
// Everything below this line and above the tests is written from the contract
// (docs/appliance.md, section 10) with plain HMAC and AES-GCM calls. It shares
// no code with stream.go, so a test that passes pins the format, not the
// implementation's idea of it.

// refStreamKey is HKDF-SHA256(ikm = key, salt, info = "happymining-backup-v1",
// length = 32), written out: one extract and one expand block (RFC 5869).
func refStreamKey(key, salt []byte) []byte {
	extract := hmac.New(sha256.New, salt)
	extract.Write(key)
	prk := extract.Sum(nil)
	expand := hmac.New(sha256.New, prk)
	expand.Write([]byte("happymining-backup-v1"))
	expand.Write([]byte{0x01})
	return expand.Sum(nil)[:32]
}

func refHeader(key, salt []byte, chunkSize uint32) []byte {
	id := sha256.Sum256(key)
	h := []byte("HMBK1\n")
	h = append(h, id[:8]...)
	h = append(h, salt...)
	return binary.BigEndian.AppendUint32(h, chunkSize)
}

func refNonce(i uint64, last bool) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n, i)
	if last {
		n[11] = 0x01
	}
	return n
}

func refGCM(t testing.TB, key, salt []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(refStreamKey(key, salt))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return gcm
}

// refChunk is one chunk on the wire: length || ciphertext || tag.
func refChunk(t testing.TB, key, header []byte, i uint64, last bool, plaintext []byte) []byte {
	t.Helper()
	salt := header[14:30]
	ct := refGCM(t, key, salt).Seal(nil, refNonce(i, last), plaintext, header)
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(ct))), ct...)
}

// refArchive encrypts pieces as chunks 0..n-1, the last one marked final.
func refArchive(t testing.TB, key, salt []byte, chunkSize uint32, pieces ...[]byte) []byte {
	t.Helper()
	header := refHeader(key, salt, chunkSize)
	out := append([]byte(nil), header...)
	for i, p := range pieces {
		out = append(out, refChunk(t, key, header, uint64(i), i == len(pieces)-1, p)...)
	}
	return out
}

// splitArchive cuts an archive into its header and its chunks (each with its
// length field).
func splitArchive(t testing.TB, data []byte) (header []byte, chunks [][]byte) {
	t.Helper()
	if len(data) < HeaderSize {
		t.Fatalf("archive of %d bytes has no header", len(data))
	}
	header, rest := data[:HeaderSize], data[HeaderSize:]
	for len(rest) > 0 {
		if len(rest) < 4 {
			t.Fatalf("dangling %d bytes", len(rest))
		}
		n := 4 + int(binary.BigEndian.Uint32(rest))
		if n > len(rest) {
			t.Fatalf("chunk of %d bytes, %d left", n, len(rest))
		}
		chunks = append(chunks, rest[:n])
		rest = rest[n:]
	}
	return header, chunks
}

func joinArchive(header []byte, chunks ...[]byte) []byte {
	out := append([]byte(nil), header...)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

// --- helpers ------------------------------------------------------------------

func randomBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// encryptWith makes an archive with the implementation, with a small chunk.
func encryptWith(t testing.TB, key Key, chunkSize uint32, plaintext []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := newEncryptWriter(&out, key, chunkSize, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// decrypt reads an archive to the end and returns what was released and the
// error that ended it (nil for a clean end).
func decrypt(key Key, archive []byte) (released []byte, err error) {
	r, err := NewDecryptReader(bytes.NewReader(archive), key)
	if err != nil {
		return nil, err
	}
	released, err = io.ReadAll(r)
	return released, err
}

// --- round trips --------------------------------------------------------------

func TestStreamRoundTripAroundChunkBoundaries(t *testing.T) {
	const chunk = 64
	key := mustNewKey(t)
	for _, size := range []int{0, 1, chunk - 1, chunk, chunk + 1, 2*chunk - 1, 2 * chunk, 2*chunk + 1, 5*chunk + 7} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			plaintext := randomBytes(t, size)
			archive := encryptWith(t, key, chunk, plaintext)

			// The layout the contract describes: full chunks, then one
			// final chunk that may be shorter (or empty, for no data).
			header, chunks := splitArchive(t, archive)
			if !bytes.Equal(header, refHeader(key[:], header[14:30], chunk)) {
				t.Fatalf("header %x", header)
			}
			wantChunks := (size + chunk - 1) / chunk
			if size == 0 {
				wantChunks = 1
			}
			if len(chunks) != wantChunks {
				t.Fatalf("%d chunks, want %d", len(chunks), wantChunks)
			}
			for i, c := range chunks {
				want := chunk + 16
				if i == len(chunks)-1 {
					want = size - chunk*(len(chunks)-1) + 16
				}
				if len(c)-4 != want {
					t.Fatalf("chunk %d has %d bytes, want %d", i, len(c)-4, want)
				}
			}

			got, err := decrypt(key, archive)
			if err != nil || !bytes.Equal(got, plaintext) {
				t.Fatalf("round trip: %v", err)
			}
		})
	}
}

func TestStreamWriterAcceptsAnyWriteSizes(t *testing.T) {
	const chunk = 32
	key := mustNewKey(t)
	plaintext := randomBytes(t, 7*chunk+5)
	for _, step := range []int{1, 3, chunk - 1, chunk, chunk + 1, 3 * chunk, len(plaintext)} {
		var out bytes.Buffer
		w, err := newEncryptWriter(&out, key, chunk, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		for rest := plaintext; len(rest) > 0; {
			n := min(step, len(rest))
			if m, err := w.Write(rest[:n]); err != nil || m != n {
				t.Fatalf("write: %d, %v", m, err)
			}
			rest = rest[n:]
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		// Read back through a reader that hands out one byte at a time.
		r, err := NewDecryptReader(iotestOneByte{bytes.NewReader(out.Bytes())}, key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("step %d: %v", step, err)
		}
	}
}

// iotestOneByte reads one byte per call, like testing/iotest.OneByteReader.
type iotestOneByte struct{ r io.Reader }

func (o iotestOneByte) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}

func TestStreamDefaultChunkIsOneMiB(t *testing.T) {
	if ChunkSize != 1048576 || HeaderSize != 34 {
		t.Fatalf("ChunkSize %d, HeaderSize %d", ChunkSize, HeaderSize)
	}
	key := mustNewKey(t)
	for _, size := range []int{0, 1, ChunkSize, 2*ChunkSize + 123} {
		plaintext := randomBytes(t, size)
		var out bytes.Buffer
		w, err := NewEncryptWriter(&out, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(plaintext); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		header, chunks := splitArchive(t, out.Bytes())
		if got := binary.BigEndian.Uint32(header[30:]); got != 1048576 {
			t.Fatalf("chunk_size in the header is %d", got)
		}
		if size > ChunkSize && len(chunks[0]) != 4+ChunkSize+16 {
			t.Fatalf("first chunk has %d bytes", len(chunks[0]))
		}
		if size == ChunkSize && len(chunks) != 1 {
			t.Fatalf("exactly one chunk of data gave %d chunks", len(chunks))
		}
		got, err := decrypt(key, out.Bytes())
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("size %d: %v", size, err)
		}
	}
}

// --- the format is the contract's ----------------------------------------------

// Archives produced by a separate implementation (Python: hashlib, struct and
// the cryptography package's HKDF and AESGCM) for key = 00..1f and
// salt = a0..af.
const (
	// chunk_size 1048576, plaintext "hello, backup".
	vectorA = "484d424b310a630dcd2966c43366a0a1a2a3a4a5a6a7a8a9aaabacadaeaf001000000000001dfcdfb7aef53754bfabad6ab40c3473a2914fbdad8b6e1e713954ced3b0"
	// chunk_size 16, plaintext 00..27 (40 bytes): chunks of 16, 16 and 8.
	vectorB = "484d424b310a630dcd2966c43366a0a1a2a3a4a5a6a7a8a9aaabacadaeaf0000001000000020a174175c980ab3b7c2d3b9f9b290cb210b7155d0158877e33287699c67859cc2000000201c68d78d09e7169304e13e728b3e8ef323d263436845ca3106b6c464fe1490b500000018f8991b9f095c75d536cc5af6cc41a2cdb1d42a41d5b0109e"
	// chunk_size 1048576, no plaintext: one empty final chunk.
	vectorE = "484d424b310a630dcd2966c43366a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00100000000000105b9669874b406b1f532932bef7d6386d"
)

func vectorSalt() []byte {
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = 0xa0 + byte(i)
	}
	return salt
}

func seq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestStreamMatchesExternalVectors(t *testing.T) {
	key := testKey()
	for _, v := range []struct {
		name      string
		hex       string
		chunkSize uint32
		plaintext []byte
	}{
		{"A", vectorA, 1048576, []byte("hello, backup")},
		{"B", vectorB, 16, seq(40)},
		{"E", vectorE, 1048576, nil},
	} {
		t.Run(v.name, func(t *testing.T) {
			want, err := hex.DecodeString(v.hex)
			if err != nil {
				t.Fatal(err)
			}
			// The writer produces exactly these bytes...
			var out bytes.Buffer
			w, err := newEncryptWriter(&out, key, v.chunkSize, bytes.NewReader(vectorSalt()))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(v.plaintext); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out.Bytes(), want) {
				t.Fatalf("writer output\n got %x\nwant %x", out.Bytes(), want)
			}
			// ...the reader opens them...
			got, err := decrypt(key, want)
			if err != nil || !bytes.Equal(got, v.plaintext) {
				t.Fatalf("reader: %q, %v", got, err)
			}
			// ...and so does the test's own implementation of the contract.
			if ref := refArchive(t, key[:], vectorSalt(), v.chunkSize, cut(v.plaintext, int(v.chunkSize))...); !bytes.Equal(ref, want) {
				t.Fatalf("the test's reference implementation disagrees with the vector:\n got %x\nwant %x", ref, want)
			}
		})
	}
}

// cut splits b into pieces of n bytes; no data gives one empty piece.
func cut(b []byte, n int) [][]byte {
	var pieces [][]byte
	for len(b) > n {
		pieces = append(pieces, b[:n])
		b = b[n:]
	}
	return append(pieces, b)
}

// The known-answer test asked for by the contract: take an archive made by
// NewEncryptWriter, derive the stream key and open the first chunk with plain
// crypto calls written here, independently of stream.go.
func TestStreamFirstChunkOpensWithPlainCryptoCalls(t *testing.T) {
	key := mustNewKey(t)
	plaintext := randomBytes(t, ChunkSize+1000)
	var out bytes.Buffer
	w, err := NewEncryptWriter(&out, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	archive := out.Bytes()

	// header = "HMBK1\n" || key_id (8) || salt (16) || chunk_size (uint32 BE)
	header := archive[:34]
	if string(header[:6]) != "HMBK1\n" {
		t.Fatalf("magic %q", header[:6])
	}
	id := sha256.Sum256(key[:])
	if !bytes.Equal(header[6:14], id[:8]) {
		t.Fatalf("key_id %x, want %x", header[6:14], id[:8])
	}
	salt := header[14:30]
	if bytes.Equal(salt, make([]byte, 16)) {
		t.Fatal("the salt is all zero")
	}
	if !bytes.Equal(header[30:34], []byte{0x00, 0x10, 0x00, 0x00}) {
		t.Fatalf("chunk_size %x", header[30:34])
	}

	// stream_key = HKDF-SHA256(key, salt, "happymining-backup-v1", 32)
	extract := hmac.New(sha256.New, salt)
	extract.Write(key[:])
	expand := hmac.New(sha256.New, extract.Sum(nil))
	expand.Write([]byte("happymining-backup-v1\x01"))
	streamKey := expand.Sum(nil)

	block, err := aes.NewCipher(streamKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	// chunk 0 = uint32 BE length || AES-256-GCM(stream_key, nonce_0, plaintext_0, AAD = header)
	length := binary.BigEndian.Uint32(archive[34:38])
	if length != ChunkSize+16 {
		t.Fatalf("first chunk length %d", length)
	}
	first := archive[38 : 38+length]
	nonce0 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00} // i = 0, not the last chunk
	got, err := gcm.Open(nil, nonce0, first, header)
	if err != nil {
		t.Fatalf("the first chunk does not open with the contract's key, nonce and AAD: %v", err)
	}
	if !bytes.Equal(got, plaintext[:ChunkSize]) {
		t.Fatal("the first chunk does not hold the first megabyte of plaintext")
	}
	// The second and final chunk: i = 1, last = 0x01.
	rest := archive[38+length:]
	length2 := binary.BigEndian.Uint32(rest[:4])
	nonce1 := []byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0x01}
	got, err = gcm.Open(nil, nonce1, rest[4:4+length2], header)
	if err != nil || !bytes.Equal(got, plaintext[ChunkSize:]) {
		t.Fatalf("final chunk: %v", err)
	}
	if len(rest) != 4+int(length2) {
		t.Fatal("bytes after the final chunk")
	}
	// The same chunk with the other value of the last flag does not open.
	if _, err := gcm.Open(nil, []byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0x00}, rest[4:4+length2], header); err == nil {
		t.Fatal("the final flag is not part of the nonce")
	}
}

// An archive written by someone else may end with an empty final chunk after
// full chunks ("the final chunk may be shorter or empty").
func TestStreamReaderAcceptsIndependentArchives(t *testing.T) {
	key := mustNewKey(t)
	salt := randomBytes(t, 16)
	data := randomBytes(t, 48)
	for name, pieces := range map[string][][]byte{
		"empty only":             {nil},
		"short final":            {data[:16], data[16:20]},
		"full final":             {data[:16], data[16:32]},
		"empty final after full": {data[:16], data[16:32], nil},
		"three full":             {data[:16], data[16:32], data[32:48]},
	} {
		archive := refArchive(t, key[:], salt, 16, pieces...)
		got, err := decrypt(key, archive)
		if err != nil || !bytes.Equal(got, bytes.Join(pieces, nil)) {
			t.Errorf("%s: %x, %v", name, got, err)
		}
	}
}

func TestReadHeaderNeedsNoKey(t *testing.T) {
	key := mustNewKey(t)
	archive := encryptWith(t, key, 64, []byte("x"))
	h, err := ReadHeader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	if h.KeyID() != KeyID(key) || h.ChunkSize != 64 || h.KeyTag != keyTag(key) || !bytes.Equal(h.Salt[:], archive[14:30]) {
		t.Fatalf("header %+v", h)
	}
	for name, data := range map[string][]byte{
		"empty":        nil,
		"short":        archive[:33],
		"other magic":  append([]byte("HMBK2\n"), archive[6:]...),
		"gzip":         append([]byte{0x1f, 0x8b, 8, 0}, make([]byte, 60)...),
		"chunk zero":   append(append([]byte(nil), archive[:30]...), 0, 0, 0, 0),
		"chunk 1MiB+1": append(append([]byte(nil), archive[:30]...), 0x00, 0x10, 0x00, 0x01),
		"chunk max":    append(append([]byte(nil), archive[:30]...), 0xff, 0xff, 0xff, 0xff),
	} {
		if _, err := ReadHeader(bytes.NewReader(data)); !errors.Is(err, ErrBadHeader) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := NewDecryptReader(bytes.NewReader(data), key); !errors.Is(err, ErrBadHeader) {
			t.Errorf("%s (decrypt): %v", name, err)
		}
	}
	failing := io.MultiReader(bytes.NewReader(archive[:10]), failingReader{})
	if _, err := ReadHeader(failing); err == nil || errors.Is(err, ErrBadHeader) || !errors.Is(err, errInput) {
		t.Errorf("an input failure must be reported as such: %v", err)
	}
}

var errInput = errors.New("input failed")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errInput }

// --- tampering ------------------------------------------------------------------

// tamperFixture is an archive of four chunks (16, 16, 16 and 8 bytes).
type tamperFixture struct {
	key       Key
	plaintext []byte
	header    []byte
	chunks    [][]byte
}

func newTamperFixture(t *testing.T) tamperFixture {
	t.Helper()
	f := tamperFixture{key: mustNewKey(t), plaintext: randomBytes(t, 56)}
	archive := encryptWith(t, f.key, 16, f.plaintext)
	f.header, f.chunks = splitArchive(t, archive)
	if len(f.chunks) != 4 {
		t.Fatalf("%d chunks", len(f.chunks))
	}
	return f
}

// expect decrypts archive and checks the error, that whatever was released
// before it is a prefix of the true plaintext of exactly releasedChunks
// chunks, and that the error says nothing about the key or the data.
func (f tamperFixture) expect(t *testing.T, name string, archive []byte, want error, releasedChunks int) {
	t.Helper()
	got, err := decrypt(f.key, archive)
	if !errors.Is(err, want) {
		t.Errorf("%s: error %v, want %v", name, err, want)
		return
	}
	if !bytes.Equal(got, f.plaintext[:min(16*releasedChunks, len(f.plaintext))]) {
		t.Errorf("%s: released %d bytes, want the first %d chunks", name, len(got), releasedChunks)
	}
	f.checkNoLeak(t, name, err)
}

func (f tamperFixture) checkNoLeak(t *testing.T, name string, err error) {
	t.Helper()
	msg := strings.ToLower(err.Error())
	for _, secret := range []string{
		hex.EncodeToString(f.key[:]), hex.EncodeToString(f.key[:8]),
		strings.TrimPrefix(FormatRecoveryKey(f.key), "hmrk1-")[:9],
		hex.EncodeToString(f.plaintext[:8]), string(f.plaintext[:8]),
	} {
		if strings.Contains(msg, strings.ToLower(secret)) {
			t.Errorf("%s: the error leaks: %v", name, err)
		}
	}
}

func flip(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	out[i] ^= 0x01
	return out
}

func TestStreamDetectsTruncation(t *testing.T) {
	f := newTamperFixture(t)
	c := f.chunks
	f.expect(t, "final chunk missing", joinArchive(f.header, c[0], c[1], c[2]), ErrTruncated, 2)
	f.expect(t, "two chunks missing", joinArchive(f.header, c[0], c[1]), ErrTruncated, 1)
	f.expect(t, "only the first chunk", joinArchive(f.header, c[0]), ErrTruncated, 0)
	f.expect(t, "header only", joinArchive(f.header), ErrTruncated, 0)
	// The chunk before the cut is whole and authentic, and is released.
	f.expect(t, "cut inside the final chunk", joinArchive(f.header, c[0], c[1], c[2], c[3][:10]), ErrTruncated, 3)
	// A chunk followed by half a length field is held back.
	f.expect(t, "cut inside a length field", joinArchive(f.header, c[0], c[1], c[2][:2]), ErrTruncated, 1)
	f.expect(t, "cut inside the first length field", joinArchive(f.header, c[0][:3]), ErrTruncated, 0)

	// Every proper prefix of the archive is refused, and what was released
	// before the error is true plaintext.
	whole := joinArchive(f.header, c...)
	for n := 0; n < len(whole); n++ {
		got, err := decrypt(f.key, whole[:n])
		if err == nil {
			t.Fatalf("a prefix of %d of %d bytes was accepted", n, len(whole))
		}
		if !errors.Is(err, ErrTruncated) && !errors.Is(err, ErrBadHeader) {
			t.Fatalf("prefix of %d bytes: %v", n, err)
		}
		if !bytes.HasPrefix(f.plaintext, got) {
			t.Fatalf("prefix of %d bytes released something else than the plaintext", n)
		}
	}
	if got, err := decrypt(f.key, whole); err != nil || !bytes.Equal(got, f.plaintext) {
		t.Fatalf("the untouched archive: %v", err)
	}
}

func TestStreamUnclosedWriterIsTruncated(t *testing.T) {
	key := mustNewKey(t)
	var out bytes.Buffer
	w, err := newEncryptWriter(&out, key, 16, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(randomBytes(t, 100)); err != nil {
		t.Fatal(err)
	}
	// No Close: a backup that failed half-way.
	if _, err := decrypt(key, out.Bytes()); !errors.Is(err, ErrTruncated) {
		t.Fatalf("an unfinished archive was not refused as truncated: %v", err)
	}
}

func TestStreamDetectsReorderingDuplicationAndRemoval(t *testing.T) {
	f := newTamperFixture(t)
	c := f.chunks
	f.expect(t, "first two chunks swapped", joinArchive(f.header, c[1], c[0], c[2], c[3]), ErrKeyOrHeader, 0)
	f.expect(t, "middle chunks swapped", joinArchive(f.header, c[0], c[2], c[1], c[3]), ErrCorrupt, 1)
	f.expect(t, "chunk repeated", joinArchive(f.header, c[0], c[1], c[1], c[2], c[3]), ErrCorrupt, 2)
	f.expect(t, "first chunk repeated", joinArchive(f.header, c[0], c[0], c[1], c[2], c[3]), ErrCorrupt, 1)
	f.expect(t, "middle chunk removed", joinArchive(f.header, c[0], c[2], c[3]), ErrCorrupt, 1)
	f.expect(t, "first chunk removed", joinArchive(f.header, c[1], c[2], c[3]), ErrKeyOrHeader, 0)
	f.expect(t, "final chunk moved first", joinArchive(f.header, c[3], c[0], c[1], c[2]), ErrKeyOrHeader, 0)
	f.expect(t, "final chunk in the middle", joinArchive(f.header, c[0], c[3], c[1], c[2]), ErrCorrupt, 1)

	// A chunk from another archive of the same key (another salt).
	other := encryptWith(t, f.key, 16, f.plaintext)
	_, oc := splitArchive(t, other)
	f.expect(t, "chunk of another archive", joinArchive(f.header, c[0], oc[1], c[2], c[3]), ErrCorrupt, 1)
}

func TestStreamDetectsDataAfterTheFinalChunk(t *testing.T) {
	f := newTamperFixture(t)
	c := f.chunks
	whole := joinArchive(f.header, c...)
	// Nothing of the final chunk is released when something follows it.
	f.expect(t, "a chunk after the final chunk", append(append([]byte(nil), whole...), c[1]...), ErrTrailingData, 3)
	f.expect(t, "the final chunk twice", append(append([]byte(nil), whole...), c[3]...), ErrTrailingData, 3)
	f.expect(t, "one byte after", append(append([]byte(nil), whole...), 0x00), ErrTrailingData, 3)
	f.expect(t, "four bytes after", append(append([]byte(nil), whole...), 0, 0, 0, 0x10), ErrTrailingData, 3)
	f.expect(t, "garbage after", append(append([]byte(nil), whole...), randomBytes(t, 100)...), ErrTrailingData, 3)

	// An empty final chunk followed by more.
	key := mustNewKey(t)
	empty := refArchive(t, key[:], randomBytes(t, 16), 16, nil)
	if _, err := decrypt(key, append(empty, 0x00)); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("after an empty final chunk: %v", err)
	}
}

func TestStreamDetectsBadChunkLengths(t *testing.T) {
	f := newTamperFixture(t)
	c := f.chunks
	setLen := func(chunk []byte, n uint32) []byte {
		out := append([]byte(nil), chunk...)
		binary.BigEndian.PutUint32(out, n)
		return out
	}
	f.expect(t, "one byte too long", joinArchive(f.header, setLen(c[0], 16+16+1), c[1], c[2], c[3]), ErrChunkLength, 0)
	f.expect(t, "over-long later chunk", joinArchive(f.header, c[0], setLen(c[1], 1<<20), c[2], c[3]), ErrChunkLength, 1)
	f.expect(t, "shorter than a tag", joinArchive(f.header, setLen(c[0], 15), c[1], c[2], c[3]), ErrChunkLength, 0)
	f.expect(t, "zero", joinArchive(f.header, setLen(c[0], 0), c[1], c[2], c[3]), ErrChunkLength, 0)

	// The largest length a field can hold must be refused before anything
	// is allocated for it.
	huge := joinArchive(f.header, setLen(c[0], 0xffffffff))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := decrypt(f.key, huge)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrChunkLength) {
		t.Fatalf("4 GiB chunk: %v", err)
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 1<<20 {
		t.Fatalf("a 4 GiB length field made the reader allocate %d bytes", grown)
	}

	// A length that is valid but lies (shorter than the real chunk) shifts
	// everything after it: authentication fails.
	f.expect(t, "length lies", joinArchive(f.header, setLen(c[0], 20), c[1], c[2], c[3]), ErrKeyOrHeader, 0)

	// An authentic chunk that is not the last and is not full: only a writer
	// holding the key can make one, and the format does not allow it.
	key := mustNewKey(t)
	header := refHeader(key[:], randomBytes(t, 16), 16)
	short := joinArchive(header,
		refChunk(t, key[:], header, 0, false, []byte("short")),
		refChunk(t, key[:], header, 1, true, []byte("end")))
	if got, err := decrypt(key, short); !errors.Is(err, ErrChunkLength) || len(got) != 0 {
		t.Fatalf("short non-final chunk: %q, %v", got, err)
	}
}

func TestStreamDetectsAlteredBytes(t *testing.T) {
	f := newTamperFixture(t)
	c := f.chunks
	f.expect(t, "bit flipped in the first chunk", joinArchive(f.header, flip(c[0], 10), c[1], c[2], c[3]), ErrKeyOrHeader, 0)
	f.expect(t, "bit flipped in the first tag", joinArchive(f.header, flip(c[0], len(c[0])-1), c[1], c[2], c[3]), ErrKeyOrHeader, 0)
	f.expect(t, "bit flipped in a later chunk", joinArchive(f.header, c[0], c[1], flip(c[2], 4), c[3]), ErrCorrupt, 2)
	f.expect(t, "bit flipped in the final chunk", joinArchive(f.header, c[0], c[1], c[2], flip(c[3], 6)), ErrCorrupt, 3)
	f.expect(t, "bit flipped in the final tag", joinArchive(f.header, c[0], c[1], c[2], flip(c[3], len(c[3])-1)), ErrCorrupt, 3)

	// The header is authenticated with every chunk.
	f.expect(t, "salt altered", joinArchive(flip(f.header, 20), c...), ErrKeyOrHeader, 0)
	smaller := append([]byte(nil), f.header...)
	binary.BigEndian.PutUint32(smaller[30:], 32) // a valid value, but not the one that was signed
	f.expect(t, "chunk size altered", joinArchive(smaller, c...), ErrKeyOrHeader, 0)

	// Every single-bit change anywhere in the archive is refused.
	whole := joinArchive(f.header, c...)
	for i := range whole {
		if got, err := decrypt(f.key, flip(whole, i)); err == nil {
			t.Fatalf("a bit flipped at byte %d went unnoticed (%d bytes released)", i, len(got))
		} else if !bytes.HasPrefix(f.plaintext, got) {
			t.Fatalf("a bit flipped at byte %d released altered plaintext", i)
		}
	}
}

// countingSource counts the bytes taken from an archive.
type countingSource struct {
	r io.Reader
	n int
}

func (c *countingSource) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestStreamWrongKeyIsReportedBeforeAnythingIsRead(t *testing.T) {
	f := newTamperFixture(t)
	other := mustNewKey(t)
	src := &countingSource{r: bytes.NewReader(joinArchive(f.header, f.chunks...))}
	r, err := NewDecryptReader(src, other)
	if r != nil || !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong key: reader %v, error %v", r, err)
	}
	if src.n != HeaderSize {
		t.Fatalf("%d bytes were read before the wrong key was reported; only the header (%d) may be", src.n, HeaderSize)
	}
	var mismatch *KeyMismatchError
	if !errors.As(err, &mismatch) || mismatch.ArchiveKeyID != KeyID(f.key) || mismatch.KeyID != KeyID(other) {
		t.Fatalf("mismatch detail %+v", mismatch)
	}
	// The message names the two key ids (which are public) and nothing else.
	if !strings.Contains(err.Error(), KeyID(f.key)) || !strings.Contains(err.Error(), KeyID(other)) {
		t.Fatalf("message %q", err)
	}
	f.checkNoLeak(t, "wrong key", err)
	msg := err.Error()
	for _, k := range []Key{f.key, other} {
		if strings.Contains(msg, hex.EncodeToString(k[:])) || strings.Contains(msg, hex.EncodeToString(k[4:12])) {
			t.Fatalf("the error leaks key bytes: %v", err)
		}
	}
	// It is a different error from every other one.
	for _, e := range []error{ErrKeyOrHeader, ErrCorrupt, ErrTruncated, ErrTrailingData, ErrChunkLength, ErrBadHeader} {
		if errors.Is(err, e) {
			t.Fatalf("ErrWrongKey is also %v", e)
		}
	}
}

func TestStreamDetectsWrongKeyID(t *testing.T) {
	f := newTamperFixture(t)
	other := mustNewKey(t)
	otherTag := keyTag(other)

	// The header is rewritten to name another key.
	forged := append([]byte(nil), f.header...)
	copy(forged[6:14], otherTag[:])
	archive := joinArchive(forged, f.chunks...)

	// With the real key: the archive says it is not for this key.
	if _, err := decrypt(f.key, archive); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("real key, forged id: %v", err)
	}
	// With the key it names: the id check passes, the first chunk does not
	// authenticate, and nothing is released.
	got, err := decrypt(other, archive)
	if !errors.Is(err, ErrKeyOrHeader) || len(got) != 0 {
		t.Fatalf("named key: %d bytes, %v", len(got), err)
	}
	if errors.Is(err, ErrWrongKey) || errors.Is(err, ErrCorrupt) {
		t.Fatalf("the errors are not distinct: %v", err)
	}
	f.checkNoLeak(t, "forged key id", err)

	// One bit of the key id: no longer this key's archive.
	if _, err := decrypt(f.key, joinArchive(flip(f.header, 6), f.chunks...)); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("key id bit: %v", err)
	}
	// The last byte of the 8-byte field counts too, although the reported
	// key id shows only the first four.
	if _, err := decrypt(f.key, joinArchive(flip(f.header, 13), f.chunks...)); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("key id last byte: %v", err)
	}
}

func TestStreamErrorsAreDistinctAndSticky(t *testing.T) {
	all := []error{ErrBadHeader, ErrWrongKey, ErrKeyOrHeader, ErrCorrupt, ErrTruncated, ErrTrailingData, ErrChunkLength}
	for i, a := range all {
		for j, b := range all {
			if i != j && (errors.Is(a, b) || a.Error() == b.Error()) {
				t.Errorf("%v and %v are not distinct", a, b)
			}
		}
	}
	f := newTamperFixture(t)
	c := f.chunks
	r, err := NewDecryptReader(bytes.NewReader(joinArchive(f.header, c[0], flip(c[1], 8), c[2], c[3])), f.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	// After an error the reader gives nothing more, ever.
	for i := 0; i < 3; i++ {
		n, err := r.Read(make([]byte, 64))
		if n != 0 || !errors.Is(err, ErrCorrupt) {
			t.Fatalf("read after an error: %d, %v", n, err)
		}
	}
	// After a clean end it stays at the end.
	r, err = NewDecryptReader(bytes.NewReader(joinArchive(f.header, c...)), f.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err != nil {
		t.Fatal(err)
	}
	if n, err := r.Read(make([]byte, 8)); n != 0 || err != io.EOF {
		t.Fatalf("read after the end: %d, %v", n, err)
	}
}

func TestStreamInputFailureIsNotTruncation(t *testing.T) {
	f := newTamperFixture(t)
	whole := joinArchive(f.header, f.chunks...)
	src := io.MultiReader(bytes.NewReader(whole[:60]), failingReader{})
	r, err := NewDecryptReader(src, f.key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(r)
	if !errors.Is(err, errInput) || errors.Is(err, ErrTruncated) {
		t.Fatalf("an input failure was reported as %v", err)
	}
}

// --- the writer -----------------------------------------------------------------

type failAfter struct {
	n   int
	err error
}

func (f *failAfter) Write(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, f.err
	}
	f.n--
	return len(p), nil
}

func TestEncryptWriterStates(t *testing.T) {
	key := mustNewKey(t)
	if _, err := NewEncryptWriter(io.Discard, Key{}); !errors.Is(err, ErrZeroKey) {
		t.Fatalf("zero key: %v", err)
	}
	if _, err := newEncryptWriter(io.Discard, key, 0, rand.Reader); err == nil {
		t.Fatal("chunk size 0 accepted")
	}
	if _, err := newEncryptWriter(io.Discard, key, ChunkSize+1, rand.Reader); err == nil {
		t.Fatal("chunk size above 1 MiB accepted")
	}

	var out bytes.Buffer
	w, err := newEncryptWriter(&out, key, 16, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if out.Len() != HeaderSize {
		t.Fatalf("the header is not written at once: %d bytes", out.Len())
	}
	if _, err := w.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	size := out.Len()
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := w.Write([]byte("more")); !errors.Is(err, ErrClosed) {
		t.Fatalf("write after Close: %v", err)
	}
	if out.Len() != size {
		t.Fatal("something was written after Close")
	}

	// A failure of the underlying writer is kept and returned by Close.
	boom := errors.New("disk full")
	if _, err := newEncryptWriter(&failAfter{n: 0, err: boom}, key, 16, rand.Reader); !errors.Is(err, boom) {
		t.Fatalf("header write failure: %v", err)
	}
	w, err = newEncryptWriter(&failAfter{n: 2, err: boom}, key, 16, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.Write(randomBytes(t, 200))
	if !errors.Is(err, boom) {
		t.Fatalf("write failure: %v", err)
	}
	if _, err := w.Write([]byte("x")); !errors.Is(err, boom) {
		t.Fatalf("write after a failure: %v", err)
	}
	if err := w.Close(); !errors.Is(err, boom) {
		t.Fatalf("Close after a failure: %v", err)
	}

	// Two archives of the same data differ (random salt) and have different
	// stream keys.
	a, b := encryptWith(t, key, 16, []byte("same")), encryptWith(t, key, 16, []byte("same"))
	if bytes.Equal(a[14:30], b[14:30]) || bytes.Equal(a[HeaderSize:], b[HeaderSize:]) {
		t.Fatal("two archives share a salt or a ciphertext")
	}
}

// Memory use must not grow with the archive: 64 MiB go through a writer and a
// reader, and the allocations stay around the four chunk buffers.
func TestStreamMemoryIsBoundedByTheChunkSize(t *testing.T) {
	if testing.Short() {
		t.Skip("streams 64 MiB")
	}
	key := mustNewKey(t)
	const total = 64 << 20
	block := randomBytes(t, 1<<16)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	pr, pw := io.Pipe()
	go func() {
		w, err := NewEncryptWriter(pw, key)
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		for sent := 0; sent < total; sent += len(block) {
			if _, err := w.Write(block); err != nil {
				pw.CloseWithError(err)
				return
			}
		}
		pw.CloseWithError(w.Close())
	}()
	r, err := NewDecryptReader(pr, key)
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, r)
	if err != nil || n != total {
		t.Fatalf("%d bytes, %v", n, err)
	}
	runtime.ReadMemStats(&after)
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 12<<20 {
		t.Fatalf("streaming %d MiB allocated %d MiB", total>>20, grown>>20)
	}
}
