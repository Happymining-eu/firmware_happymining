package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// HMBK1 constants (docs/appliance.md, section 10).
const (
	// Magic starts every archive.
	Magic = "HMBK1\n"
	// HeaderSize is the size of the header in bytes.
	HeaderSize = len(Magic) + keyTagSize + saltSize + 4
	// ChunkSize is the plaintext size of every chunk but the last, and the
	// chunk_size written in the header of every archive made here.
	ChunkSize = 1 << 20

	keyTagSize = 8
	saltSize   = 16
	tagSize    = 16 // AES-GCM tag
	streamInfo = "happymining-backup-v1"
)

// Header is the decoded HMBK1 header. It holds nothing secret.
type Header struct {
	// KeyTag is the header's key_id field: the first 8 bytes of SHA-256 of the
	// key the archive was made with.
	KeyTag [keyTagSize]byte
	// Salt is the HKDF salt of this archive.
	Salt [saltSize]byte
	// ChunkSize is the plaintext size of every chunk but the last.
	ChunkSize uint32
}

// KeyID returns the key id in the form the machine reports it (8 hexadecimal
// characters), comparable with KeyID(key).
func (h Header) KeyID() string { return hex.EncodeToString(h.KeyTag[:4]) }

func (h Header) bytes() [HeaderSize]byte {
	var b [HeaderSize]byte
	n := copy(b[:], Magic)
	n += copy(b[n:], h.KeyTag[:])
	n += copy(b[n:], h.Salt[:])
	binary.BigEndian.PutUint32(b[n:], h.ChunkSize)
	return b
}

func parseHeader(b [HeaderSize]byte) (Header, error) {
	if string(b[:len(Magic)]) != Magic {
		return Header{}, ErrBadHeader
	}
	var h Header
	n := len(Magic)
	n += copy(h.KeyTag[:], b[n:n+keyTagSize])
	n += copy(h.Salt[:], b[n:n+saltSize])
	h.ChunkSize = binary.BigEndian.Uint32(b[n:])
	// The contract fixes chunk_size at 1048576. A smaller value is harmless
	// and accepted; a larger one would make the reader allocate what the
	// archive asks for, and is refused.
	if h.ChunkSize == 0 || h.ChunkSize > ChunkSize {
		return Header{}, ErrBadHeader
	}
	return h, nil
}

// ReadHeader reads the 34-byte header from r and returns it. It needs no key:
// it is how a tool tells which key an archive wants (Header.KeyID) before
// asking for the recovery key. An input that is too short or does not start
// with the magic is ErrBadHeader.
func ReadHeader(r io.Reader) (Header, error) {
	h, _, err := readHeader(r)
	return h, err
}

func readHeader(r io.Reader) (Header, [HeaderSize]byte, error) {
	var raw [HeaderSize]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Header{}, raw, ErrBadHeader
		}
		return Header{}, raw, fmt.Errorf("backup: read archive header: %w", err)
	}
	h, err := parseHeader(raw)
	return h, raw, err
}

// newStreamAEAD derives the stream key of one archive and returns its cipher.
func newStreamAEAD(key Key, salt []byte) (cipher.AEAD, error) {
	streamKey, err := hkdf.Key(sha256.New, key[:], salt, streamInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("backup: derive stream key: %w", err)
	}
	block, err := aes.NewCipher(streamKey)
	clear(streamKey)
	if err != nil {
		return nil, fmt.Errorf("backup: cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("backup: cipher: %w", err)
	}
	return aead, nil
}

// chunkNonce is nonce_i: uint64 BE i || 0x00 0x00 0x00 || last.
func chunkNonce(index uint64, last bool) [12]byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[:8], index)
	if last {
		n[11] = 1
	}
	return n
}

// NewEncryptWriter writes the HMBK1 header to w and returns a writer that
// encrypts what is written to it. Close writes the final chunk; an archive
// whose writer was not closed has no final chunk and every reader refuses it
// as truncated, so a failed backup must simply not be closed. Close does not
// close w.
//
// Memory use is two chunks (about 2 MiB) whatever the size of the stream.
func NewEncryptWriter(w io.Writer, key Key) (io.WriteCloser, error) {
	return newEncryptWriter(w, key, ChunkSize, rand.Reader)
}

// newEncryptWriter is NewEncryptWriter with the chunk size and the source of
// the salt chosen by the caller; tests use it for small chunks and fixed
// vectors. Archives made by the agent always use ChunkSize.
func newEncryptWriter(w io.Writer, key Key, chunkSize uint32, random io.Reader) (*encryptWriter, error) {
	if key.IsZero() {
		return nil, ErrZeroKey
	}
	if chunkSize == 0 || chunkSize > ChunkSize {
		return nil, fmt.Errorf("%w: chunk size", ErrInvalidConfig)
	}
	h := Header{KeyTag: keyTag(key), ChunkSize: chunkSize}
	if _, err := io.ReadFull(random, h.Salt[:]); err != nil {
		return nil, fmt.Errorf("backup: generate salt: %w", err)
	}
	aead, err := newStreamAEAD(key, h.Salt[:])
	if err != nil {
		return nil, err
	}
	e := &encryptWriter{
		w:      w,
		aead:   aead,
		header: h.bytes(),
		buf:    make([]byte, 0, chunkSize),
		out:    make([]byte, 0, 4+int(chunkSize)+tagSize),
	}
	if _, err := w.Write(e.header[:]); err != nil {
		return nil, fmt.Errorf("backup: write archive header: %w", err)
	}
	return e, nil
}

type encryptWriter struct {
	w      io.Writer
	aead   cipher.AEAD
	header [HeaderSize]byte
	buf    []byte // plaintext of the chunk being filled
	out    []byte // length || ciphertext || tag of the chunk being written
	index  uint64
	err    error
	closed bool
}

// Write buffers p and writes every chunk that is known not to be the last.
func (e *encryptWriter) Write(p []byte) (int, error) {
	if e.closed {
		return 0, ErrClosed
	}
	if e.err != nil {
		return 0, e.err
	}
	n := 0
	for len(p) > 0 {
		// A full buffer is written only when more data arrives: until then
		// it may still be the final chunk.
		if len(e.buf) == cap(e.buf) {
			if err := e.flush(false); err != nil {
				return n, err
			}
		}
		c := copy(e.buf[len(e.buf):cap(e.buf)], p)
		e.buf = e.buf[:len(e.buf)+c]
		p = p[c:]
		n += c
	}
	return n, nil
}

// Close writes the final chunk (which may be empty or full).
func (e *encryptWriter) Close() error {
	if e.closed {
		return e.err
	}
	e.closed = true
	if e.err == nil {
		_ = e.flush(true)
	}
	clear(e.buf[:cap(e.buf)])
	return e.err
}

func (e *encryptWriter) flush(last bool) error {
	nonce := chunkNonce(e.index, last)
	e.out = e.aead.Seal(e.out[:4], nonce[:], e.buf, e.header[:])
	binary.BigEndian.PutUint32(e.out[:4], uint32(len(e.out)-4))
	if _, err := e.w.Write(e.out); err != nil {
		e.err = fmt.Errorf("backup: write archive: %w", err)
		return e.err
	}
	e.index++
	e.buf = e.buf[:0]
	return nil
}

// NewDecryptReader reads the HMBK1 header from r, checks that key is the key
// the archive names, and returns a reader of the plaintext.
//
// A key that is not the archive's is reported here, before anything is read
// further: the error is a *KeyMismatchError and errors.Is(err, ErrWrongKey).
//
// The reader releases plaintext one authenticated chunk at a time, never
// before the chunk's tag is verified. It returns io.EOF only after the final
// chunk was verified and the input ended right after it; otherwise it returns
// one of ErrKeyOrHeader, ErrCorrupt, ErrTruncated, ErrTrailingData or
// ErrChunkLength. Bytes delivered before such an error are authentic but the
// stream is not whole: a caller that got an error must discard what it built.
//
// Memory use is two chunks whatever the size of the stream.
func NewDecryptReader(r io.Reader, key Key) (io.Reader, error) {
	h, raw, err := readHeader(r)
	if err != nil {
		return nil, err
	}
	want := keyTag(key)
	if subtle.ConstantTimeCompare(h.KeyTag[:], want[:]) != 1 {
		return nil, &KeyMismatchError{ArchiveKeyID: h.KeyID(), KeyID: KeyID(key)}
	}
	aead, err := newStreamAEAD(key, h.Salt[:])
	if err != nil {
		return nil, err
	}
	return &decryptReader{
		r:         r,
		aead:      aead,
		header:    raw,
		chunkSize: int(h.ChunkSize),
		ct:        make([]byte, 0, int(h.ChunkSize)+tagSize),
		plain:     make([]byte, 0, int(h.ChunkSize)),
	}, nil
}

type decryptReader struct {
	r         io.Reader
	aead      cipher.AEAD
	header    [HeaderSize]byte
	chunkSize int
	index     uint64
	ct        []byte // ciphertext || tag of the current chunk
	plain     []byte // its plaintext
	pending   []byte // part of plain not yet delivered
	// next is the length field of the following chunk, read ahead to learn
	// whether the current chunk is the last one.
	next     [4]byte
	haveNext bool
	done     bool
	err      error
}

func (d *decryptReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(d.pending) == 0 {
		if d.err != nil {
			return 0, d.err
		}
		if d.done {
			return 0, io.EOF
		}
		if err := d.nextChunk(); err != nil {
			// Nothing of a chunk that ended in an error is released.
			d.err = err
			d.pending = nil
			clear(d.plain[:cap(d.plain)])
			return 0, err
		}
	}
	n := copy(p, d.pending)
	d.pending = d.pending[n:]
	return n, nil
}

// readInput fills b. It reports how many bytes it got and whether the input
// ended (cleanly, at any point); another failure of the input is returned as
// an error.
func (d *decryptReader) readInput(b []byte) (n int, ended bool, err error) {
	n, err = io.ReadFull(d.r, b)
	switch {
	case err == nil:
		return n, false, nil
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return n, true, nil
	default:
		return n, false, fmt.Errorf("backup: read archive: %w", err)
	}
}

// nextChunk reads, authenticates and decrypts one chunk into d.pending.
func (d *decryptReader) nextChunk() error {
	if !d.haveNext {
		// Only reached for the first chunk: later length fields are read
		// ahead below. A stream always has at least its final chunk.
		_, ended, err := d.readInput(d.next[:])
		if err != nil {
			return err
		}
		if ended {
			return ErrTruncated
		}
	}
	d.haveNext = false
	length := int(binary.BigEndian.Uint32(d.next[:]))
	if length < tagSize || length > d.chunkSize+tagSize {
		return ErrChunkLength
	}
	d.ct = d.ct[:length]
	if _, ended, err := d.readInput(d.ct); err != nil {
		return err
	} else if ended {
		return ErrTruncated
	}

	// Whether this chunk is the last one is not written in the stream: it is
	// part of the nonce. The last chunk is the one the input ends after.
	n, ended, err := d.readInput(d.next[:])
	if err != nil {
		return err
	}
	atEnd := ended && n == 0
	d.haveNext = !ended

	if atEnd {
		if d.open(true) {
			d.done = true
			return nil
		}
		if d.open(false) {
			// An authentic chunk that says it is not the last, and nothing
			// after it: the end of the archive is missing.
			return ErrTruncated
		}
		return d.authFailure()
	}
	if d.open(false) {
		if length != d.chunkSize+tagSize {
			// Authentic, but every chunk before the last is full.
			return ErrChunkLength
		}
		if ended {
			// The next length field is cut short.
			return ErrTruncated
		}
		d.index++
		return nil
	}
	if d.open(true) {
		return ErrTrailingData
	}
	return d.authFailure()
}

// open authenticates and decrypts the current chunk as final or not. On
// success the plaintext is in d.pending. The ciphertext is left untouched, so
// that the other nonce can be tried.
func (d *decryptReader) open(last bool) bool {
	nonce := chunkNonce(d.index, last)
	plain, err := d.aead.Open(d.plain[:0], nonce[:], d.ct, d.header[:])
	if err != nil {
		d.pending = nil
		return false
	}
	d.plain = plain
	d.pending = plain
	return true
}

// authFailure names an authentication failure. Before the first chunk has
// authenticated nothing is known about the key or the header; after it both
// are proven right and the fault is in the chunk.
func (d *decryptReader) authFailure() error {
	if d.index == 0 {
		return ErrKeyOrHeader
	}
	return ErrCorrupt
}
