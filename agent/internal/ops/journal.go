package ops

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
)

// JournalFileName is the journal file name inside the state directory.
const JournalFileName = "ops.journal"

// Journal bounds.
const (
	// Retention is how long an entry is kept. An entry is only pruned when it
	// is older than this AND the operation it describes has expired, so that
	// pruning can never reopen a replay window.
	Retention = 30 * 24 * time.Hour
	// MaxEntries bounds the journal. When it is full no new operation is
	// accepted (which is safe: nothing executes).
	MaxEntries = 10000
	maxLine    = 8 * 1024
)

// ErrJournalFull is returned when the journal cannot take another operation.
var ErrJournalFull = errors.New("local operation journal is full")

// Events of a journal line.
const (
	eventStart = "start"
	eventFinal = "final"
)

// line is one append-only JSON line.
type line struct {
	At        string `json:"at"`
	Event     string `json:"event"`
	ID        string `json:"id"`
	Type      string `json:"type,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Status    string `json:"status,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Record is what the journal knows about one operation id.
type Record struct {
	ID        string
	Type      string
	FirstSeen time.Time
	ExpiresAt time.Time
	// Final is the final status that was decided ("" if execution started
	// and no outcome was recorded, for example because of a crash or reboot).
	Final  string
	Detail string
}

// Journal is the persistent replay-protection journal: an append-only file,
// fsynced on every append. It is not safe for concurrent use.
type Journal struct {
	path    string
	f       *os.File
	records map[string]*Record
	now     func() time.Time
}

// OpenJournal loads the journal, prunes old entries and opens it for append.
func OpenJournal(path string, now func() time.Time) (*Journal, error) {
	if now == nil {
		now = time.Now
	}
	j := &Journal{path: path, records: map[string]*Record{}, now: now}
	if err := j.load(); err != nil {
		return nil, err
	}
	if err := j.compact(); err != nil {
		return nil, err
	}
	return j, nil
}

func (j *Journal) load() error {
	f, err := os.Open(j.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open operation journal: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, maxLine), maxLine)
	for sc.Scan() {
		var l line
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil || l.ID == "" {
			// A torn last line after a crash: ignore it. The id of an
			// operation is only acted upon after its line was fsynced.
			continue
		}
		j.apply(l)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read operation journal: %w", err)
	}
	return nil
}

func (j *Journal) apply(l line) {
	at, _ := time.Parse(protocol.TimeFormat, l.At)
	rec := j.records[l.ID]
	if rec == nil {
		rec = &Record{ID: l.ID, FirstSeen: at}
		j.records[l.ID] = rec
	}
	if l.Type != "" {
		rec.Type = l.Type
	}
	if l.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, l.ExpiresAt); err == nil {
			rec.ExpiresAt = t
		}
	}
	if l.Event == eventFinal {
		rec.Final, rec.Detail = l.Status, l.Detail
	}
}

func (j *Journal) lines(rec *Record) []line {
	first := line{
		At: protocol.FormatTime(rec.FirstSeen), Event: eventStart, ID: rec.ID, Type: rec.Type,
	}
	if !rec.ExpiresAt.IsZero() {
		first.ExpiresAt = protocol.FormatTime(rec.ExpiresAt)
	}
	if rec.Final == "" {
		return []line{first}
	}
	first.Event, first.Status, first.Detail = eventFinal, rec.Final, rec.Detail
	return []line{first}
}

// compact drops prunable entries and rewrites the file atomically.
func (j *Journal) compact() error {
	if j.f != nil {
		_ = j.f.Close()
		j.f = nil
	}
	now := j.now()
	var buf []byte
	for id, rec := range j.records {
		if now.Sub(rec.FirstSeen) > Retention && rec.ExpiresAt.Before(now) {
			delete(j.records, id)
			continue
		}
		for _, l := range j.lines(rec) {
			raw, err := json.Marshal(l)
			if err != nil {
				return err
			}
			buf = append(append(buf, raw...), '\n')
		}
	}
	if err := os.MkdirAll(filepath.Dir(j.path), 0o750); err != nil {
		return fmt.Errorf("create journal directory: %w", err)
	}
	if err := fsx.WriteFileAtomic(j.path, buf, 0o600, nil); err != nil {
		return fmt.Errorf("rewrite operation journal: %w", err)
	}
	f, err := os.OpenFile(j.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open operation journal for append: %w", err)
	}
	j.f = f
	return nil
}

// Prune removes prunable entries. The agent calls it once a day.
func (j *Journal) Prune() error { return j.compact() }

func (j *Journal) append(l line) error {
	raw, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if len(raw)+1 > maxLine {
		return errors.New("journal line too long")
	}
	if _, err := j.f.Write(append(raw, '\n')); err != nil {
		return fmt.Errorf("append to operation journal: %w", err)
	}
	if err := j.f.Sync(); err != nil {
		return fmt.Errorf("fsync operation journal: %w", err)
	}
	return nil
}

// Lookup returns the record of an operation id, if any.
func (j *Journal) Lookup(id string) (Record, bool) {
	rec, ok := j.records[id]
	if !ok {
		return Record{}, false
	}
	return *rec, true
}

// Len returns the number of journaled operation ids.
func (j *Journal) Len() int { return len(j.records) }

// Start durably records an operation id before anything is executed.
func (j *Journal) Start(id, opType string, expiresAt time.Time) error {
	if _, dup := j.records[id]; dup {
		return fmt.Errorf("operation %s is already in the journal", id)
	}
	if len(j.records) >= MaxEntries {
		return ErrJournalFull
	}
	now := j.now()
	l := line{At: protocol.FormatTime(now), Event: eventStart, ID: id, Type: protocol.Truncate(opType, 64)}
	if !expiresAt.IsZero() {
		l.ExpiresAt = protocol.FormatTime(expiresAt)
	}
	if err := j.append(l); err != nil {
		return err
	}
	j.apply(l)
	return nil
}

// Finish durably records the final outcome of a journaled operation.
func (j *Journal) Finish(id, status, detail string) error {
	if _, ok := j.records[id]; !ok {
		return fmt.Errorf("operation %s is not in the journal", id)
	}
	l := line{
		At: protocol.FormatTime(j.now()), Event: eventFinal, ID: id,
		Status: status, Detail: protocol.Truncate(detail, 500),
	}
	if err := j.append(l); err != nil {
		return err
	}
	j.apply(l)
	return nil
}

// Close closes the journal file.
func (j *Journal) Close() error {
	if j.f == nil {
		return nil
	}
	err := j.f.Close()
	j.f = nil
	return err
}
