package applier

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// maxMountInfoBytes bounds the mount table read (a host with thousands of
// container mounts stays far below it).
const maxMountInfoBytes = 16 << 20

// MountEntry is one line of /proc/<pid>/mountinfo (proc(5)):
//
//	36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
//	(1)(2)(3)   (4)   (5)      (6)      (7)   (8) (9)   (10)         (11)
//
// Root, MountPoint and Source are unescaped: the kernel writes a space, a tab,
// a newline and a backslash in them as \040, \011, \012 and \134.
type MountEntry struct {
	ID         int
	ParentID   int
	Root       string
	MountPoint string
	// Options are the per-mount options (field 6), SuperOptions the
	// per-superblock ones (field 11).
	Options      []string
	FSType       string
	Source       string
	SuperOptions []string
}

// ReadWrite reports whether the mount is writable: "rw" per mount and not
// "ro" for the superblock.
func (m MountEntry) ReadWrite() bool {
	return hasOption(m.Options, "rw") && !hasOption(m.SuperOptions, "ro")
}

func hasOption(opts []string, want string) bool {
	for _, o := range opts {
		if o == want {
			return true
		}
	}
	return false
}

// ParseMountInfo parses a mount table. A line that does not have the format
// is an error: a table that cannot be read is not taken as "nothing mounted".
func ParseMountInfo(r io.Reader) ([]MountEntry, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxMountInfoBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxMountInfoBytes {
		return nil, fmt.Errorf("mount table larger than %d bytes", maxMountInfoBytes)
	}
	var out []MountEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if strings.TrimSpace(text) == "" {
			continue
		}
		e, err := parseMountLine(text)
		if err != nil {
			return nil, fmt.Errorf("mount table line %d: %w", line, err)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseMountLine(text string) (MountEntry, error) {
	fields := strings.Split(text, " ")
	sep := -1
	for i := 6; i < len(fields); i++ {
		if fields[i] == "-" {
			sep = i
			break
		}
	}
	if len(fields) < 10 || sep < 0 || len(fields) < sep+4 {
		return MountEntry{}, fmt.Errorf("not in mountinfo format")
	}
	var e MountEntry
	var err error
	if e.ID, err = strconv.Atoi(fields[0]); err != nil {
		return MountEntry{}, fmt.Errorf("bad mount id")
	}
	if e.ParentID, err = strconv.Atoi(fields[1]); err != nil {
		return MountEntry{}, fmt.Errorf("bad parent id")
	}
	if e.Root, err = unescapeMount(fields[3]); err != nil {
		return MountEntry{}, err
	}
	if e.MountPoint, err = unescapeMount(fields[4]); err != nil {
		return MountEntry{}, err
	}
	e.Options = strings.Split(fields[5], ",")
	e.FSType = fields[sep+1]
	if e.Source, err = unescapeMount(fields[sep+2]); err != nil {
		return MountEntry{}, err
	}
	e.SuperOptions = strings.Split(strings.Join(fields[sep+3:], " "), ",")
	return e, nil
}

// unescapeMount decodes the kernel's octal escapes (\ooo).
func unescapeMount(s string) (string, error) {
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+4 > len(s) {
			return "", fmt.Errorf("bad escape")
		}
		v, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			return "", fmt.Errorf("bad escape")
		}
		b.WriteByte(byte(v))
		i += 3
	}
	return b.String(), nil
}

// mountAt returns the entry visible at path: the last one mounted there.
func mountAt(entries []MountEntry, path string) (MountEntry, bool) {
	var found MountEntry
	ok := false
	for _, e := range entries {
		if e.MountPoint == path {
			found, ok = e, true
		}
	}
	return found, ok
}

// readMountInfo parses the helper's mount table.
func (e *Env) readMountInfo() ([]MountEntry, error) {
	data, err := readFile(e.Paths.MountInfo, maxMountInfoBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("the mount table cannot be read")
	}
	return ParseMountInfo(bytes.NewReader(data))
}

// isNetworkFS reports whether fstype is one the helper mounts.
func isNetworkFS(fstype string) bool {
	switch fstype {
	case "cifs", "smb3", "nfs", "nfs4":
		return true
	}
	return false
}
