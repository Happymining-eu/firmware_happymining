package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// RunOptions describe one backup run.
type RunOptions struct {
	// Key encrypts the archive.
	Key Key
	// Destination receives it.
	Destination Destination
	// MachineID names the archive and goes into its manifest.
	MachineID string
	// AgentVersion goes into the manifest.
	AgentVersion string
	// Items is what to save; see Item.
	Items []Item
	// Now is the time of the run (archive name and manifest). The zero value
	// means the current time.
	Now time.Time
}

// Result is the outcome of a successful Run.
type Result struct {
	// Name is the archive's name at the destination.
	Name string
	// Size is the size of the encrypted archive in bytes.
	Size int64
	// KeyID is the id of the key the archive was made with.
	KeyID string
	// Stats count what was stored.
	Stats WriteStats
}

// errPutReturned unblocks the producing side when Put returns.
var errPutReturned = errors.New("backup: the destination stopped reading")

// countingReader counts what the destination reads.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// Run makes one archive and stores it: WriteArchive, encrypted by
// NewEncryptWriter, streamed to Destination.Put through a pipe. Nothing is
// written to a temporary file and the archive is never held in memory.
//
// If reading the items fails, the encrypted stream is left without its final
// chunk and the pipe is closed with the error, so that the destination's Put
// fails and stores nothing: a run either stores a complete archive or returns
// an error. Run does not prune; call Prune after a successful run.
func Run(ctx context.Context, opts RunOptions) (Result, error) {
	if opts.Destination == nil {
		return Result{}, fmt.Errorf("%w: no destination", ErrInvalidConfig)
	}
	if opts.Key.IsZero() {
		return Result{}, ErrZeroKey
	}
	if !ValidMachineID(opts.MachineID) {
		return Result{}, fmt.Errorf("%w: machine id", ErrInvalidConfig)
	}
	if !reAgentVersion.MatchString(opts.AgentVersion) {
		return Result{}, fmt.Errorf("%w: agent version", ErrInvalidConfig)
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	name := ArchiveName(opts.MachineID, now)
	if err := checkArchiveName(name); err != nil {
		return Result{}, fmt.Errorf("%w: the run time cannot be written in an archive name", ErrInvalidConfig)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	pr, pw := io.Pipe()
	type produced struct {
		stats WriteStats
		err   error
	}
	done := make(chan produced, 1)
	go func() {
		var p produced
		enc, err := NewEncryptWriter(pw, opts.Key)
		if err == nil {
			p.stats, err = WriteArchive(ctx, enc, opts.Items, WriteOptions{
				MachineID: opts.MachineID, AgentVersion: opts.AgentVersion, CreatedAt: now,
			})
			if err == nil {
				// The final chunk is written only for a complete archive.
				err = enc.Close()
			}
		}
		p.err = err
		// A nil error ends the stream normally; anything else makes the
		// destination's read fail with it.
		_ = pw.CloseWithError(err)
		done <- p
	}()

	counter := &countingReader{r: pr}
	putErr := opts.Destination.Put(ctx, name, counter)
	// If Put returned before the end of the stream, stop the producer.
	_ = pr.CloseWithError(errPutReturned)
	p := <-done

	switch {
	case p.err != nil && !errors.Is(p.err, errPutReturned):
		// The archive could not be produced; that is the cause, whatever
		// the destination said about its interrupted upload.
		return Result{}, p.err
	case putErr != nil:
		return Result{}, putErr
	case p.err != nil:
		// Put returned success without reading the whole archive.
		return Result{}, fmt.Errorf("backup: the destination did not store the whole archive: %w", p.err)
	}
	return Result{Name: name, Size: counter.n, KeyID: KeyID(opts.Key), Stats: p.stats}, nil
}

// RestoreOptions describe one restore.
type RestoreOptions struct {
	// Key is the key of the archive, from the recovery key.
	Key Key
	// Source is the archive, as a stream (a local file, for example). When it
	// is nil, the archive Name is fetched from Destination.
	Source io.Reader
	// Destination and Name locate the archive when Source is nil.
	Destination Destination
	Name        string
	// DestDir is the directory to restore into; see ExtractArchive. It
	// should be empty or not exist.
	DestDir string
	// Extract bounds the restore; see ExtractOptions.
	Extract ExtractOptions
}

// Restore decrypts an archive and extracts it under DestDir.
//
// A key that is not the archive's is reported (ErrWrongKey) before anything is
// read further and before DestDir is touched. Any other error can come after
// part of the archive was written: on error the content of DestDir is
// incomplete and must be discarded. A nil error means the whole archive was
// authenticated to its final chunk and extracted.
//
// Restore is a local action of the person at the machine; nothing in this
// package triggers it.
func Restore(ctx context.Context, opts RestoreOptions) (ExtractResult, error) {
	if opts.DestDir == "" {
		return ExtractResult{}, fmt.Errorf("%w: no directory to restore into", ErrInvalidConfig)
	}
	src := opts.Source
	if src == nil {
		if opts.Destination == nil {
			return ExtractResult{}, fmt.Errorf("%w: no archive to restore", ErrInvalidConfig)
		}
		rc, err := opts.Destination.Get(ctx, opts.Name)
		if err != nil {
			return ExtractResult{}, err
		}
		defer rc.Close()
		src = rc
	}
	plain, err := NewDecryptReader(ctxReader{ctx, src}, opts.Key)
	if err != nil {
		return ExtractResult{}, err
	}
	res, err := ExtractArchive(ctx, plain, opts.DestDir, opts.Extract)
	if err != nil {
		return res, err
	}
	// ExtractArchive read its input to the end. Make sure that end is the
	// authenticated end of the encrypted stream.
	var one [1]byte
	switch n, err := plain.Read(one[:]); {
	case n != 0:
		return res, fmt.Errorf("%w: data after the end of the archive", ErrBadArchive)
	case err != io.EOF:
		if err == nil {
			err = ErrTruncated
		}
		return res, err
	}
	return res, nil
}
