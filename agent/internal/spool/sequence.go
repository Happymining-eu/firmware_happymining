package spool

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
)

// SequenceFileName is the counter file name inside the state directory.
const SequenceFileName = "seq"

// Sequence is the persistent, strictly increasing sample counter. Next
// persists the new value (atomic write + fsync) before returning it, so a
// number is never handed out twice, even across a crash.
type Sequence struct {
	path string
	last uint64
}

// OpenSequence loads the counter. floor is a lower bound known from elsewhere
// (the newest spooled sample); the counter never starts below it. A missing
// file starts at floor; an unreadable one is reported and also starts at floor.
func OpenSequence(path string, floor uint64) (*Sequence, error) {
	s := &Sequence{path: path, last: floor}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return s, nil
		}
		return s, fmt.Errorf("read sequence counter: %w", err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return s, fmt.Errorf("sequence counter %s is corrupt; continuing from %d", path, floor)
	}
	if n > s.last {
		s.last = n
	}
	return s, nil
}

// Last returns the most recently issued number.
func (s *Sequence) Last() uint64 { return s.last }

// Next persists and returns the next sequence number.
func (s *Sequence) Next() (uint64, error) {
	if s.last == math.MaxUint64 {
		return 0, errors.New("sequence counter exhausted")
	}
	n := s.last + 1
	if err := s.persist(n); err != nil {
		return 0, err
	}
	s.last = n
	return n, nil
}

// AdvanceTo raises the counter to at least n (used when the server reports a
// higher sequence than the local state knows, i.e. local state was lost).
func (s *Sequence) AdvanceTo(n uint64) error {
	if n <= s.last {
		return nil
	}
	if n > math.MaxUint64/2 {
		return fmt.Errorf("refusing to advance the sequence counter to %d", n)
	}
	if err := s.persist(n); err != nil {
		return err
	}
	s.last = n
	return nil
}

func (s *Sequence) persist(n uint64) error {
	if err := fsx.WriteFileAtomic(s.path, []byte(strconv.FormatUint(n, 10)+"\n"), 0o600, nil); err != nil {
		return fmt.Errorf("persist sequence counter: %w", err)
	}
	return nil
}
