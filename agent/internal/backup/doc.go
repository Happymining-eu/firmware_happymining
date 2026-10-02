// Package backup implements the encrypted backups of docs/appliance.md,
// section 10: the backup key and its recovery-key text, the HMBK1 stream
// encryption, the gzip(tar) archive inside it, and the two destinations (a
// directory on a mounted NAS, an S3-compatible bucket).
//
// It is a library: it decides nothing about what is saved or when, stops no
// plugin and reads no configuration. The root helper builds the list of items
// and the destination and calls Run; a local restore calls Restore.
//
// Everything streams. An archive of tens of gigabytes is never held in memory
// or in a temporary file: memory use is bounded by the stream chunk (1 MiB,
// two buffers) and, for S3, by one upload part (16 MiB by default).
//
// # Archive format HMBK1
//
//	header     = "HMBK1\n" || key_id (8 bytes: first 8 of SHA-256(key)) || salt (16 random bytes) || chunk_size (uint32 BE, 1048576)
//	stream_key = HKDF-SHA256(ikm = key, salt = salt, info = "happymining-backup-v1", length = 32)
//	chunk i    = uint32 BE length of ciphertext || AES-256-GCM(stream_key, nonce_i, plaintext_i, AAD = header)
//	nonce_i    = uint64 BE i || 0x00 0x00 0x00 || last   (last = 0x01 for the final chunk, else 0x00)
//	plaintext  = gzip( tar ), cut into chunk_size pieces; the final chunk may be shorter or empty
//
// Two points the contract leaves to the reader, as implemented here: the first
// chunk has i = 0, and the length field counts the whole AES-GCM output, that
// is the encrypted bytes followed by the 16-byte tag.
//
// # Inside the archive
//
// The first tar entry is manifest.json (format version, machine id, creation
// time, agent version, the list of items). Every other entry lives under the
// logical name of one item. Only regular files, directories and symbolic links
// are stored; owners are numeric.
//
// # Trust
//
// The archive read by a restore is untrusted input, even though it is
// authenticated: ExtractArchive refuses absolute paths, "..", hard links,
// device nodes and FIFOs, never follows a symbolic link while writing (every
// path component is opened relative to its parent with O_NOFOLLOW), never
// overwrites a file, never sets a setuid or setgid bit and bounds the number of
// entries and the total size.
//
// The backup key never appears in an error, and neither does the S3 secret
// key. File names of the saved data are kept out of error texts as well (they
// are available as a field of EntryError for a local tool).
//
// The package uses Linux system calls (openat and friends) and builds for
// Linux only, like the rest of the agent.
package backup
