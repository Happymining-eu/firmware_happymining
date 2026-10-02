package backup

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"time"
)

// Archive names: hm-backup-<machine id>-<YYYYMMDDTHHMMSSZ>.hmbk
const (
	archivePrefix   = "hm-backup-"
	archiveSuffix   = ".hmbk"
	archiveTimeForm = "20060102T150405Z"
)

var (
	// A machine id is the machine's UUID as the control plane prints it.
	// Lower-case letters, digits and inner dashes, at most 64 characters, are
	// accepted so that a machine that was never paired can still be named.
	reMachineID   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
	reArchiveName = regexp.MustCompile(`^hm-backup-([a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)-([0-9]{8}T[0-9]{6}Z)\.hmbk$`)
)

// ValidMachineID reports whether id can be part of an archive name.
func ValidMachineID(id string) bool { return reMachineID.MatchString(id) }

// ArchiveName returns the file name of the archive made by machineID at t
// (converted to UTC, cut to the second).
//
// It does not validate: if machineID is not a ValidMachineID, or t is outside
// the years 0000 to 9999, the result is not an archive name, ParseArchiveName
// refuses it and so does every Destination. Run validates before it starts.
func ArchiveName(machineID string, t time.Time) string {
	return archivePrefix + machineID + "-" + t.UTC().Format(archiveTimeForm) + archiveSuffix
}

// ParseArchiveName splits an archive name into the machine id and the time.
// Anything else is ErrInvalidName; in particular a name with a directory
// separator, a temporary upload name, or a date that does not exist.
func ParseArchiveName(name string) (machineID string, t time.Time, err error) {
	m := reArchiveName.FindStringSubmatch(name)
	if m == nil {
		return "", time.Time{}, ErrInvalidName
	}
	t, perr := time.Parse(archiveTimeForm, m[2])
	if perr != nil || t.Format(archiveTimeForm) != m[2] {
		return "", time.Time{}, ErrInvalidName
	}
	return m[1], t.UTC(), nil
}

// Prune deletes the oldest archives of machineID at dest so that at most keep
// remain, and returns the names it deleted, oldest first. Age is the time in
// the archive name.
//
// Only names that parse as archive names of exactly that machine are counted
// or deleted: other machines' archives, temporary files and anything else at
// the destination are never touched. keep must be at least 1. Call it after a
// successful run only.
//
// If a deletion fails, Prune stops and returns what it deleted so far together
// with the error.
func Prune(ctx context.Context, dest Destination, machineID string, keep int) (deleted []string, err error) {
	if dest == nil {
		return nil, fmt.Errorf("%w: no destination", ErrInvalidConfig)
	}
	if !ValidMachineID(machineID) {
		return nil, fmt.Errorf("%w: machine id", ErrInvalidConfig)
	}
	if keep < 1 {
		return nil, fmt.Errorf("%w: keep must be at least 1", ErrInvalidConfig)
	}
	entries, err := dest.List(ctx)
	if err != nil {
		return nil, err
	}
	type archive struct {
		name string
		at   time.Time
	}
	var mine []archive
	seen := make(map[string]bool)
	for _, e := range entries {
		id, at, perr := ParseArchiveName(e.Name)
		if perr != nil || id != machineID || seen[e.Name] {
			continue
		}
		seen[e.Name] = true
		mine = append(mine, archive{name: e.Name, at: at})
	}
	if len(mine) <= keep {
		return nil, nil
	}
	// Oldest first; the name breaks a tie so that the order is stable.
	sort.Slice(mine, func(i, j int) bool {
		if !mine[i].at.Equal(mine[j].at) {
			return mine[i].at.Before(mine[j].at)
		}
		return mine[i].name < mine[j].name
	})
	for _, a := range mine[:len(mine)-keep] {
		if err := ctx.Err(); err != nil {
			return deleted, err
		}
		if err := dest.Delete(ctx, a.name); err != nil {
			return deleted, fmt.Errorf("backup: prune: %w", err)
		}
		deleted = append(deleted, a.name)
	}
	return deleted, nil
}
