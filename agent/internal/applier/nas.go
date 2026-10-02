package applier

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/seal"
)

// The rules of docs/appliance.md, 4.3, checked again right where a value
// becomes part of a mount command, whatever validated it before.
var (
	reNASHost   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	reNASShare  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._$-]{0,79}$`)
	reNASExport = regexp.MustCompile(`^/[A-Za-z0-9._/-]{0,254}$`)
	reNASUser   = regexp.MustCompile(`^[^,=\\/:\s]{0,64}$`)
	reNASDomain = regexp.MustCompile(`^[A-Za-z0-9._-]{0,64}$`)
)

// maxCIFSPassword keeps the credentials line within mount.cifs' line buffer
// (4096 bytes, "password=" and the line end included).
const maxCIFSPassword = 4000

func validSubpath(sub string) bool {
	if sub == "" {
		return true
	}
	if len(sub) > 512 {
		return false
	}
	for _, seg := range strings.Split(sub, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		for _, r := range seg {
			// A comma would become a CIFS mount option (mount.cifs passes the
			// path after the share to the kernel as prefixpath=, unescaped); a
			// backslash is an SMB path separator. The document validator
			// refuses both already; this is the second check, at the mount.
			if r < 0x20 || r == 0x7f || r == ',' || r == '\\' {
				return false
			}
		}
	}
	return true
}

// checkNAS validates an entry for mounting.
func checkNAS(n appliance.NAS) error {
	if !ValidID(n.ID) || !reNASHost.MatchString(n.Host) || !validSubpath(n.Subpath) {
		return fmt.Errorf("NAS entry %s is not valid", n.ID)
	}
	if n.Access != appliance.AccessRead && n.Access != appliance.AccessWrite {
		return fmt.Errorf("NAS entry %s is not valid", n.ID)
	}
	switch n.Kind {
	case appliance.NASKindSMB:
		if !reNASShare.MatchString(n.Share) || strings.HasSuffix(n.Share, " ") ||
			!reNASUser.MatchString(n.Username) || !reNASDomain.MatchString(n.Domain) {
			return fmt.Errorf("NAS entry %s is not valid", n.ID)
		}
		if (n.Username == "") != (n.Secret == "") || (n.Secret != "" && n.Secret != appliance.NASSecretName(n.ID)) {
			return fmt.Errorf("NAS entry %s is not valid", n.ID)
		}
	case appliance.NASKindNFS:
		if !reNASExport.MatchString(n.Export) {
			return fmt.Errorf("NAS entry %s is not valid", n.ID)
		}
		for _, seg := range strings.Split(n.Export, "/") {
			if seg == ".." {
				return fmt.Errorf("NAS entry %s is not valid", n.ID)
			}
		}
	default:
		return fmt.Errorf("NAS entry %s is not valid", n.ID)
	}
	return nil
}

// nasSource is the mount source of an entry: //host/share[/subpath] or
// host:/export[/subpath].
func nasSource(n appliance.NAS) string {
	switch n.Kind {
	case appliance.NASKindSMB:
		s := "//" + n.Host + "/" + n.Share
		if n.Subpath != "" {
			s += "/" + n.Subpath
		}
		return s
	default:
		export := n.Export
		if n.Subpath != "" {
			export = strings.TrimRight(export, "/") + "/" + n.Subpath
		}
		return n.Host + ":" + export
	}
}

func nasFSType(n appliance.NAS) string {
	if n.Kind == appliance.NASKindSMB {
		return "cifs"
	}
	return "nfs"
}

// argvMount is the mount command of an entry, one of the three fixed forms:
//
//	-t cifs //host/share[/subpath] <mount point> -o ro|rw,nosuid,nodev,noexec,credentials=<file>
//	-t cifs //host/share[/subpath] <mount point> -o ro|rw,nosuid,nodev,noexec,guest
//	-t nfs  host:/export[/subpath] <mount point> -o ro|rw,nosuid,nodev,noexec
//
// Nothing from the document is in the option string: the access level picks
// ro or rw, and the credentials file name is built from the validated id.
func argvMount(n appliance.NAS, target, credFile string) []string {
	opts := "ro"
	if n.Access == appliance.AccessWrite {
		opts = "rw"
	}
	opts += ",nosuid,nodev,noexec"
	if n.Kind == appliance.NASKindSMB {
		if n.Username == "" {
			opts += ",guest"
		} else {
			opts += ",credentials=" + credFile
		}
	}
	return []string{"-t", nasFSType(n), nasSource(n), target, "-o", opts}
}

// nasFingerprint identifies what an entry mounts, so that a change (including
// a new password) is a remount. The sealed value is hashed, never opened.
func nasFingerprint(n appliance.NAS, sealed string) string {
	parts := []string{n.Kind, n.Host, n.Share, n.Export, n.Subpath, n.Username, n.Domain, n.Access, sha256Hex([]byte(sealed))}
	return sha256Hex([]byte(strings.Join(parts, "\x00")))
}

// credentialsFile is the content of a CIFS credentials file. The password
// goes only here (mode 0600), never into an argv.
func credentialsFile(n appliance.NAS, password []byte) ([]byte, error) {
	if len(password) > maxCIFSPassword {
		return nil, fmt.Errorf("the password of NAS entry %s is longer than %d bytes", n.ID, maxCIFSPassword)
	}
	if bytes.ContainsAny(password, "\n\r\x00") {
		return nil, fmt.Errorf("the password of NAS entry %s contains a line break or a NUL, which a credentials file cannot hold", n.ID)
	}
	buf := make([]byte, 0, len(password)+len(n.Username)+len(n.Domain)+32)
	buf = append(buf, "username="...)
	buf = append(buf, n.Username...)
	buf = append(buf, "\npassword="...)
	buf = append(buf, password...)
	buf = append(buf, '\n')
	if n.Domain != "" {
		buf = append(buf, "domain="...)
		buf = append(buf, n.Domain...)
		buf = append(buf, '\n')
	}
	return buf, nil
}

// nasOutcome is the result of the NAS step.
type nasOutcome struct {
	// Changed: something was mounted or unmounted.
	Changed  bool
	Failed   []string
	Disabled bool
}

// ensureNASRoot creates the mount point root (0755, root-owned).
func (e *Env) ensureNASRoot() error {
	return ensureDirs(0o755, e.OwnerUID, filepath.Dir(e.Paths.NASRoot), e.Paths.NASRoot)
}

// applyNAS mounts the document's entries and unmounts the ones HappyMining
// mounted that left the document. beforeChange is called once, before the
// first mount or unmount, so that what uses the shares can be stopped first.
func (e *Env) applyNAS(ctx context.Context, doc *appliance.Document, op *opener, beforeChange func()) nasOutcome {
	var out nasOutcome
	if !e.Switches.AllowNAS {
		_, _ = e.updateState(func(st *State) {
			for _, n := range doc.NAS {
				r := st.nas(n.ID)
				r.State, r.Detail = appliance.NASUnmounted, "mounting is disabled in helper.conf (ALLOW_NAS)"
			}
		})
		if len(doc.NAS) > 0 {
			out.Disabled = true
		}
		return out
	}
	st, err := e.loadState()
	if err != nil {
		out.Failed = append(out.Failed, "NAS: "+err.Error())
		return out
	}
	mounts, err := e.readMountInfo()
	if err != nil {
		e.recordNASAll(doc, appliance.NASError, err.Error())
		out.Failed = append(out.Failed, "NAS: "+err.Error())
		return out
	}
	if err := e.ensureNASRoot(); err != nil {
		e.recordNASAll(doc, appliance.NASError, "the mount point root cannot be used: "+err.Error())
		out.Failed = append(out.Failed, "NAS: the mount point root cannot be used")
		return out
	}
	notified := false
	change := func() {
		if !notified && beforeChange != nil {
			beforeChange()
		}
		notified = true
		out.Changed = true
	}
	inDoc := map[string]bool{}
	for _, n := range doc.NAS {
		inDoc[n.ID] = true
	}

	// Unmount what HappyMining mounted and the document no longer has.
	for _, rec := range st.NAS {
		if inDoc[rec.ID] || !ValidID(rec.ID) {
			continue
		}
		target := e.Paths.mountPoint(rec.ID)
		cur, mounted := mountAt(mounts, target)
		if rec.Mounted && mounted && isNetworkFS(cur.FSType) {
			change()
			res := e.run(ctx, timeoutMount, UmountPath, target)
			if !res.ok {
				detail := "unmounting removed NAS entry " + rec.ID + " failed: " + res.describe(op.scrub)
				out.Failed = append(out.Failed, detail)
				id := rec.ID
				_, _ = e.updateState(func(s *State) { r := s.nas(id); r.State, r.Detail = appliance.NASError, detail })
				continue
			}
		}
		id := rec.ID
		_ = removeFile(e.Paths.nasCredDir(), id+".cred")
		_, _ = e.updateState(func(s *State) { s.dropNAS(id) })
	}

	for _, n := range doc.NAS {
		state, detail := e.mountOne(ctx, n, st, mounts, op, change)
		if state == appliance.NASError {
			out.Failed = append(out.Failed, "NAS "+n.ID+": "+detail)
		}
	}
	return out
}

func (e *Env) recordNASAll(doc *appliance.Document, state, detail string) {
	_, _ = e.updateState(func(st *State) {
		for _, n := range doc.NAS {
			r := st.nas(n.ID)
			r.State, r.Detail = state, clipText(detail, 300)
		}
	})
}

// mountOne brings one entry to "mounted" and records the outcome.
func (e *Env) mountOne(ctx context.Context, n appliance.NAS, st *State, mounts []MountEntry, op *opener, change func()) (string, string) {
	record := func(state, detail string, mounted bool, fstype, fp string) (string, string) {
		detail = clipText(detail, 300)
		_, _ = e.updateState(func(s *State) {
			r := s.nas(n.ID)
			r.State, r.Detail, r.Mounted = state, detail, mounted
			if mounted {
				r.FSType, r.Fingerprint = fstype, fp
			} else {
				r.FSType, r.Fingerprint = "", ""
			}
		})
		return state, detail
	}
	if err := checkNAS(n); err != nil {
		return record(appliance.NASError, err.Error(), false, "", "")
	}
	target := e.Paths.mountPoint(n.ID)
	fp := nasFingerprint(n, op.sealed[n.Secret])
	rec, had := st.findNAS(n.ID)
	cur, mounted := mountAt(mounts, target)
	ours := had && rec.Mounted && mounted && isNetworkFS(cur.FSType)
	switch {
	case ours && rec.Fingerprint == fp:
		return record(appliance.NASMounted, "", true, rec.FSType, fp)
	case mounted && !ours:
		// Never unmount what HappyMining did not mount.
		return record(appliance.NASError, "something HappyMining did not mount is mounted at the mount point; it is left alone", false, "", "")
	case ours:
		change()
		res := e.run(ctx, timeoutMount, UmountPath, target)
		if !res.ok {
			return record(appliance.NASError, "the entry changed but the old share could not be unmounted: "+res.describe(op.scrub), true, rec.FSType, rec.Fingerprint)
		}
		_, _ = e.updateState(func(s *State) { r := s.nas(n.ID); r.Mounted, r.Fingerprint = false, "" })
	}

	if err := ensureDir(target, 0o755, e.OwnerUID); err != nil {
		return record(appliance.NASError, "the mount point cannot be used: "+err.Error(), false, "", "")
	}
	credFile := e.Paths.credFile(n.ID)
	if n.Kind == appliance.NASKindSMB && n.Username != "" {
		plain, err := op.open(n.Secret)
		if err != nil {
			return record(appliance.NASError, "secret "+n.Secret+" is "+err.Error(), false, "", "")
		}
		content, cerr := credentialsFile(n, plain)
		seal.Wipe(plain)
		if cerr != nil {
			return record(appliance.NASError, cerr.Error(), false, "", "")
		}
		if err := e.ensureStateDir(); err != nil {
			wipeBytes(content)
			return record(appliance.NASError, "the credentials file cannot be written", false, "", "")
		}
		werr := writeFile(e.Paths.nasCredDir(), n.ID+".cred", content, 0o600)
		wipeBytes(content)
		if werr != nil {
			return record(appliance.NASError, "the credentials file cannot be written", false, "", "")
		}
	} else {
		_ = removeFile(e.Paths.nasCredDir(), n.ID+".cred")
	}
	change()
	res := e.run(ctx, timeoutMount, MountPath, argvMount(n, target, credFile)...)
	if !res.ok {
		return record(appliance.NASError, "mount failed: "+res.describe(op.scrub), false, "", "")
	}
	// The mount must now be visible in the mount table.
	if after, err := e.readMountInfo(); err == nil {
		if m, ok := mountAt(after, target); !ok || !isNetworkFS(m.FSType) {
			return record(appliance.NASError, "mount reported success but the share is not in the mount table", false, "", "")
		}
	}
	return record(appliance.NASMounted, "", true, nasFSType(n), fp)
}

// nasStates reports the document's entries from the mount table and the
// recorded outcomes. It runs nothing.
func nasStates(doc *appliance.Document, st *State, mounts []MountEntry, mountErr error, p Paths) []appliance.NASState {
	out := make([]appliance.NASState, 0, len(doc.NAS))
	for _, n := range doc.NAS {
		rec, _ := st.findNAS(n.ID)
		s := appliance.NASState{ID: n.ID, State: appliance.NASUnmounted, Detail: rec.Detail}
		if mountErr != nil {
			s.State, s.Detail = appliance.NASError, "the mount table cannot be read"
		} else if m, ok := mountAt(mounts, p.mountPoint(n.ID)); ok && isNetworkFS(m.FSType) {
			s.State, s.Detail = appliance.NASMounted, ""
			if n.Access == appliance.AccessRead && m.ReadWrite() {
				s.Detail = "mounted read-write although the entry is read-only"
			}
		} else if rec.State == appliance.NASError {
			s.State = appliance.NASError
		} else if rec.State == appliance.NASMounted {
			s.Detail = "no longer mounted"
		}
		out = append(out, s)
	}
	return out
}

// mountedReadWrite checks that the share of a NAS entry is mounted at its
// mount point, writable, and was mounted by HappyMining.
func (e *Env) mountedReadWrite(id string, st *State) error {
	mounts, err := e.readMountInfo()
	if err != nil {
		return err
	}
	m, ok := mountAt(mounts, e.Paths.mountPoint(id))
	if !ok || !isNetworkFS(m.FSType) {
		return fmt.Errorf("NAS entry %s is not mounted", id)
	}
	if rec, had := st.findNAS(id); !had || !rec.Mounted {
		return fmt.Errorf("NAS entry %s was not mounted by HappyMining", id)
	}
	if !m.ReadWrite() {
		return fmt.Errorf("NAS entry %s is not mounted read-write", id)
	}
	return nil
}
