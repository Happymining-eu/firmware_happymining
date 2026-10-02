// Package applier is the engine of the privileged helper for the appliance
// (docs/appliance.md, sections 2, 4, 6, 7, 8, 9 and 10): it validates and
// persists the desired-state document, applies it (NAS mounts, the plugin
// network, the catalog plugins through Docker Compose, the vectorizer's
// configuration), runs the jobs (vectorizer sync, plugin restart, backup),
// installs signed firmware releases with a rollback guard, and gathers the
// state the agent reports.
//
// Two kinds of entry points exist, matching the process layout:
//
//   - quick ones, used by the socket-activated helper (one process per
//     request, at most 180 s, tight sandbox): Status, QuickApply, QuickRunJob,
//     QuickUpdateInstall. They read files, validate, persist and start a
//     heavy unit with `systemctl start --no-block`; they never run Docker,
//     mount, back up or run dpkg themselves;
//   - heavy ones, run as root by dedicated oneshot units: ApplyStored, RunJob,
//     InstallStaged, UpdateGuard; and the local administrator's commands
//     (SecretSet, BackupInit, BackupRestore, Purge, VectorizerToken).
//
// Everything that touches the system goes through an execx.Runner with a
// fixed absolute program path and an argv array. No value from a document
// reaches an argv except validated ids, validated hosts, shares, exports and
// subpaths in the fixed mount forms, image references from the installed
// catalog, and the catalog's post_start argv with {item} from a validated
// list setting. Every file-system root is in Paths, so tests run entirely in
// temporary directories.
//
// Secrets are opened only to write the file that needs them (a Compose env
// file, a CIFS credentials file, an S3 destination) and the plaintext buffers
// are wiped right after; they never reach an argv, a log or audit line,
// state.json, a result or an error.
package applier

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/config"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/execx"
)

// Env is what every entry point works with.
type Env struct {
	Paths    Paths
	Runner   execx.Runner
	Switches config.Helper
	// OwnerUID must own the helper's own files, the catalog, the profile and
	// the release keys (0 in production; tests use their own uid).
	OwnerUID uint32
	// AgentUID is the unprivileged agent's uid: the owner of its downloads.
	AgentUID uint32
	// Version is the installed agent package's version.
	Version string
	// Now returns the current time (UTC is applied by the callers).
	Now func() time.Time
	// Sleep waits between retries.
	Sleep func(time.Duration)
	// Audit receives one line per event. It never receives a secret.
	Audit func(string)
	// HasDocker reports whether the Docker CLI is installed.
	HasDocker func() bool
	// VectorizerGID is the group the vectorizer container runs as; nil means
	// the image's own (VectorizerContainerGID). Tests set their own group.
	VectorizerGID *int
}

// VectorizerContainerGID is the group of the user the vectorizer image runs
// as (USER 10001:10001 in appliance/vectorizer/Dockerfile). Its configuration
// directory and files are given to that group, read-only, so that the
// container can read them without running as root.
const VectorizerContainerGID = 10001

func (e *Env) vectorizerGID() int {
	if e.VectorizerGID != nil {
		return *e.VectorizerGID
	}
	return VectorizerContainerGID
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func (e *Env) sleep(d time.Duration) {
	if e.Sleep != nil {
		e.Sleep(d)
		return
	}
	time.Sleep(d)
}

func (e *Env) audit(format string, args ...any) {
	if e.Audit != nil {
		e.Audit(fmt.Sprintf(format, args...))
	}
}

func (e *Env) hasDocker() bool {
	if e.HasDocker != nil {
		return e.HasDocker()
	}
	fi, err := os.Stat(DockerPath)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// check refuses an Env that is not completely configured.
func (e *Env) check() error {
	if e == nil || e.Runner == nil {
		return fmt.Errorf("helper engine is not configured")
	}
	return e.Paths.Check()
}

// cmdResult is the outcome of one command.
type cmdResult struct {
	ok     bool
	code   int
	stdout []byte
	stderr []byte
	err    error
}

// run executes one fixed command, audits its argv (which never holds a
// secret) and its outcome.
func (e *Env) run(ctx context.Context, timeout time.Duration, path string, args ...string) cmdResult {
	e.audit("run: %s", strings.Join(append([]string{path}, args...), " "))
	res, err := e.Runner.Run(ctx, timeout, path, args...)
	out := cmdResult{stdout: res.Stdout, stderr: res.Stderr, code: res.ExitCode, err: err}
	out.ok = err == nil && res.ExitCode == 0
	if !out.ok {
		// Only the status: stderr goes into details after scrubbing, never
		// into the audit trail.
		if err != nil {
			e.audit("run: %s could not run or timed out", path)
		} else {
			e.audit("run: %s exited with status %d", path, res.ExitCode)
		}
	}
	return out
}

// describe renders a failure for a detail: the exit status and the last line
// of stderr, bounded, without control characters, and with every secret the
// scrubber knows removed.
func (r cmdResult) describe(s *scrubber) string {
	if r.err != nil {
		return clipText(s.scrub(r.err.Error()), 200)
	}
	if r.ok {
		return ""
	}
	line := lastLine(r.stderr)
	if line == "" {
		return fmt.Sprintf("exit status %d", r.code)
	}
	return fmt.Sprintf("exit status %d: %s", r.code, clipText(s.scrub(line), 240))
}

// lastLine returns the last non-empty line of b as valid UTF-8 text.
func lastLine(b []byte) string {
	b = bytes.ToValidUTF8(b, []byte("?"))
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return ""
}

// clipText removes control characters and cuts s to max runes.
func clipText(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= max {
			break
		}
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// joinDetails joins non-empty details with "; " and bounds the result.
func joinDetails(parts []string, max int) string {
	var keep []string
	for _, p := range parts {
		if p != "" {
			keep = append(keep, p)
		}
	}
	return clipText(strings.Join(keep, "; "), max)
}
