// Package spool is the agent's on-disk telemetry buffer and its persistent
// sequence counter.
//
// One sample is one file named after its zero-padded sequence number, written
// atomically. The spool has a byte quota; when a new sample does not fit, the
// oldest samples are dropped first and counted.
package spool

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
)

const (
	suffix = ".json"
	// MaxSampleBytes bounds a single spooled sample. A full sample (32 GPUs,
	// 16 disks, 16 services) is far below this.
	MaxSampleBytes = 64 * 1024
	// deviceMarker records which device the spooled samples belong to.
	deviceMarker = ".device"
)

// Entry is one spooled sample.
type Entry struct {
	Seq  uint64
	Data []byte
}

type item struct {
	seq  uint64
	size int64
}

// Spool is not safe for concurrent use; the agent drives it from one goroutine.
type Spool struct {
	dir     string
	quota   int64
	items   []item // sorted by seq, oldest first
	size    int64
	dropped uint64
}

func name(seq uint64) string { return fmt.Sprintf("%020d%s", seq, suffix) }

func parseName(n string) (uint64, bool) {
	if !strings.HasSuffix(n, suffix) || len(n) != 20+len(suffix) {
		return 0, false
	}
	seq, err := strconv.ParseUint(strings.TrimSuffix(n, suffix), 10, 64)
	if err != nil {
		return 0, false
	}
	return seq, true
}

// Open opens (and creates if needed) the spool directory, removes leftovers of
// interrupted writes and indexes the existing samples.
func Open(dir string, quotaBytes int64) (*Spool, error) {
	if quotaBytes < MaxSampleBytes {
		return nil, fmt.Errorf("spool quota %d is smaller than one sample (%d bytes)", quotaBytes, MaxSampleBytes)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create spool directory: %w", err)
	}
	s := &Spool{dir: dir, quota: quotaBytes}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read spool directory: %w", err)
	}
	for _, e := range entries {
		if fsx.IsTempName(e.Name()) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
			continue
		}
		seq, ok := parseName(e.Name())
		if !ok || !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		s.items = append(s.items, item{seq: seq, size: info.Size()})
		s.size += info.Size()
	}
	sort.Slice(s.items, func(i, j int) bool { return s.items[i].seq < s.items[j].seq })
	// A lowered quota takes effect at start-up.
	s.evict(0)
	return s, nil
}

// evict drops the oldest samples until need more bytes fit in the quota.
func (s *Spool) evict(need int64) int {
	n := 0
	for len(s.items) > 0 && s.size+need > s.quota {
		s.removeAt(0)
		s.dropped++
		n++
	}
	return n
}

func (s *Spool) removeAt(i int) {
	it := s.items[i]
	_ = os.Remove(filepath.Join(s.dir, name(it.seq)))
	s.size -= it.size
	s.items = append(s.items[:i], s.items[i+1:]...)
}

// Put stores one sample. It returns how many old samples were dropped to make
// room. Sequence numbers must be strictly increasing.
func (s *Spool) Put(seq uint64, data []byte) (evicted int, err error) {
	if len(data) == 0 || len(data) > MaxSampleBytes {
		return 0, fmt.Errorf("sample of %d bytes is outside 1..%d", len(data), MaxSampleBytes)
	}
	if n := len(s.items); n > 0 && s.items[n-1].seq >= seq {
		return 0, fmt.Errorf("sequence %d is not greater than the newest spooled sequence %d", seq, s.items[n-1].seq)
	}
	evicted = s.evict(int64(len(data)))
	if err := fsx.WriteFileAtomic(filepath.Join(s.dir, name(seq)), data, 0o600, nil); err != nil {
		return evicted, fmt.Errorf("spool sample: %w", err)
	}
	s.items = append(s.items, item{seq: seq, size: int64(len(data))})
	s.size += int64(len(data))
	return evicted, nil
}

// Peek returns the oldest samples, at most maxCount and at most maxBytes in
// total (always at least one if the spool is not empty). Files that vanished,
// are oversized or are not valid JSON are removed and counted as dropped.
func (s *Spool) Peek(maxCount int, maxBytes int) []Entry {
	var out []Entry
	total := 0
	for i := 0; i < len(s.items) && len(out) < maxCount; {
		it := s.items[i]
		data, err := os.ReadFile(filepath.Join(s.dir, name(it.seq)))
		if err != nil || len(data) == 0 || len(data) > MaxSampleBytes || !json.Valid(data) {
			s.removeAt(i)
			s.dropped++
			continue
		}
		if len(out) > 0 && total+len(data) > maxBytes {
			break
		}
		out = append(out, Entry{Seq: it.seq, Data: data})
		total += len(data)
		i++
	}
	return out
}

// Delete removes acknowledged samples.
func (s *Spool) Delete(seqs []uint64) error {
	if len(seqs) == 0 {
		return nil
	}
	gone := make(map[uint64]bool, len(seqs))
	for _, seq := range seqs {
		gone[seq] = true
	}
	var firstErr error
	kept := s.items[:0]
	for _, it := range s.items {
		if !gone[it.seq] {
			kept = append(kept, it)
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, name(it.seq))); err != nil && !errors.Is(err, fs.ErrNotExist) {
			if firstErr == nil {
				firstErr = err
			}
			kept = append(kept, it)
			continue
		}
		s.size -= it.size
	}
	s.items = kept
	if err := fsx.SyncDir(s.dir); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// Drop removes samples that will never be sent and counts them as dropped.
func (s *Spool) Drop(seqs []uint64) error {
	before := len(s.items)
	err := s.Delete(seqs)
	s.dropped += uint64(before - len(s.items))
	return err
}

// Purge drops every sample (used when the device identity changes).
func (s *Spool) Purge() error {
	seqs := make([]uint64, len(s.items))
	for i, it := range s.items {
		seqs[i] = it.seq
	}
	return s.Drop(seqs)
}

// Len returns the number of spooled samples.
func (s *Spool) Len() int { return len(s.items) }

// Size returns the spooled bytes.
func (s *Spool) Size() int64 { return s.size }

// Quota returns the configured quota in bytes.
func (s *Spool) Quota() int64 { return s.quota }

// Dropped returns how many samples were dropped since Open (quota eviction,
// unreadable files and explicit drops).
func (s *Spool) Dropped() uint64 { return s.dropped }

// HighestSeq returns the newest spooled sequence number, or 0.
func (s *Spool) HighestSeq() uint64 {
	if len(s.items) == 0 {
		return 0
	}
	return s.items[len(s.items)-1].seq
}

// Device returns the device id the spool content belongs to ("" if unknown).
func (s *Spool) Device() string {
	data, err := os.ReadFile(filepath.Join(s.dir, deviceMarker))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// SetDevice records the device id the spool content belongs to.
func (s *Spool) SetDevice(id string) error {
	return fsx.WriteFileAtomic(filepath.Join(s.dir, deviceMarker), []byte(id+"\n"), 0o600, nil)
}

// Stat reports the number and total size of spooled samples in dir without
// opening the spool. happyminingctl status uses it.
func Stat(dir string) (count int, bytes int64, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, err
	}
	for _, e := range entries {
		if _, ok := parseName(e.Name()); !ok {
			continue
		}
		if info, err := e.Info(); err == nil {
			count++
			bytes += info.Size()
		}
	}
	return count, bytes, nil
}
