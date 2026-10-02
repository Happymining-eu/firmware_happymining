package appliance

import (
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/seal"
)

// Reported is the "appliance" object of a heartbeat request (section 6.1):
// what the machine runs and how applying the last document went. Its JSON
// encoding is exactly the contract's.
//
// It must never hold a secret, a listing of a NAS path, a file name from a
// NAS or text of a document. Sanitize enforces the bounds; it cannot know
// what a secret looks like, so the details are redacted by whoever fills
// them, before Sanitize.
//
// The times are RFC 3339 in UTC ("2026-10-02T02:30:00Z"), or empty when the
// event has not happened yet.
type Reported struct {
	Schema          int             `json:"schema"`
	Control         string          `json:"control"`
	AppliedRevision int64           `json:"applied_revision"`
	ApplyStatus     string          `json:"apply_status"`
	ApplyDetail     string          `json:"apply_detail"`
	Mode            string          `json:"mode"`
	SealPublicKey   string          `json:"seal_public_key"`
	Capabilities    Capabilities    `json:"capabilities"`
	Catalog         []CatalogEntry  `json:"catalog"`
	Plugins         []PluginState   `json:"plugins"`
	NAS             []NASState      `json:"nas"`
	Secrets         []SecretState   `json:"secrets"`
	Vectorizer      VectorizerState `json:"vectorizer"`
	Backup          BackupState     `json:"backup"`
	Update          UpdateState     `json:"update"`
	Schedules       []ScheduleState `json:"schedules"`
}

// Capabilities says what the machine's helper is allowed and able to do.
type Capabilities struct {
	Plugins bool `json:"plugins"`
	NAS     bool `json:"nas"`
	Backup  bool `json:"backup"`
	Update  bool `json:"update"`
	Docker  bool `json:"docker"`
}

// PluginState is the reported state of one plugin.
type PluginState struct {
	ID      string `json:"id"`
	State   string `json:"state"`
	Detail  string `json:"detail"`
	Version string `json:"version"`
	Ports   []int  `json:"ports"`
}

// NASState is the reported state of one NAS entry.
type NASState struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

// SecretState is the reported state of one secret: its name and whether it
// opens, never anything of its value.
type SecretState struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

// VectorizerState is the reported state of the vectorizer: counters only, no
// file names.
type VectorizerState struct {
	State        string `json:"state"`
	LastRunAt    string `json:"last_run_at"`
	LastOKAt     string `json:"last_ok_at"`
	FilesIndexed int64  `json:"files_indexed"`
	FilesFailed  int64  `json:"files_failed"`
	FilesSkipped int64  `json:"files_skipped"`
	Chunks       int64  `json:"chunks"`
	Detail       string `json:"detail"`
}

// BackupState is the reported state of backups. KeyID is the first 8
// hexadecimal characters of the SHA-256 of the backup key; the key itself is
// never reported.
type BackupState struct {
	State         string `json:"state"`
	KeyPresent    bool   `json:"key_present"`
	KeyID         string `json:"key_id"`
	LastOKAt      string `json:"last_ok_at"`
	LastSizeBytes int64  `json:"last_size_bytes"`
	Detail        string `json:"detail"`
}

// UpdateState is the reported state of firmware updates.
type UpdateState struct {
	CurrentVersion string `json:"current_version"`
	State          string `json:"state"`
	TargetVersion  string `json:"target_version"`
	Detail         string `json:"detail"`
}

// ScheduleState is the reported state of one schedule.
type ScheduleState struct {
	ID         string `json:"id"`
	LastRunAt  string `json:"last_run_at"`
	LastStatus string `json:"last_status"`
	NextRunAt  string `json:"next_run_at"`
}

var reBackupKeyID = regexp.MustCompile(`^[0-9a-f]{8}$`)

// Sanitize forces the report into the bounds of section 6.1, in place:
//
//   - schema is 1; a negative revision, counter or size becomes 0;
//   - every list keeps at most 32 entries, and never is null;
//   - every string keeps at most 128 characters, a detail at most 500;
//     control characters become spaces and invalid UTF-8 is replaced;
//   - a state that is not one the contract lists becomes "error" where the
//     list has it (plugin, NAS, vectorizer, backup and update states) and
//     "unknown" elsewhere (control, apply_status, mode, secret state,
//     last_status);
//   - an entry whose id or secret name is not well formed is dropped, as is
//     a port outside 1–65535;
//   - a sealing key that is not well formed, a backup key id that is not 8
//     hexadecimal characters and a time that is not RFC 3339 become empty;
//     a time is rewritten in UTC.
//
// It does not look for secrets: redact the details first.
func (r *Reported) Sanitize() {
	r.Schema = DocumentSchema
	r.Control = oneOfOr(r.Control, StateUnknown, ControlCloud, ControlLocal)
	r.AppliedRevision = nonNegative(r.AppliedRevision)
	r.ApplyStatus = oneOfOr(r.ApplyStatus, StateUnknown, ApplyApplied, ApplyPartial, ApplyRejected, ApplyDisabled, ApplyPending)
	r.ApplyDetail = clip(r.ApplyDetail, MaxReportedDetail)
	r.Mode = oneOfOr(r.Mode, StateUnknown, ModeVast, ModePrivateAI, ModeVectorize)
	if seal.CheckPublicKey(r.SealPublicKey) != nil {
		r.SealPublicKey = ""
	}

	catalog := make([]CatalogEntry, 0, len(r.Catalog))
	for _, e := range r.Catalog {
		if reID.MatchString(e.ID) && len(catalog) < MaxReportedList {
			catalog = append(catalog, CatalogEntry{ID: e.ID, Version: clip(e.Version, MaxReportedString)})
		}
	}
	r.Catalog = catalog

	plugins := make([]PluginState, 0, len(r.Plugins))
	for _, p := range r.Plugins {
		if !reID.MatchString(p.ID) || len(plugins) >= MaxReportedList {
			continue
		}
		ports := make([]int, 0, len(p.Ports))
		for _, port := range p.Ports {
			if port >= 1 && port <= 65535 && len(ports) < MaxReportedList {
				ports = append(ports, port)
			}
		}
		plugins = append(plugins, PluginState{
			ID: p.ID,
			State: oneOfOr(p.State, PluginError, PluginRunning, PluginStarting, PluginStopped, PluginBlocked,
				PluginError, PluginNotInCatalog),
			Detail:  clip(p.Detail, MaxReportedDetail),
			Version: clip(p.Version, MaxReportedString),
			Ports:   ports,
		})
	}
	r.Plugins = plugins

	nas := make([]NASState, 0, len(r.NAS))
	for _, n := range r.NAS {
		if reID.MatchString(n.ID) && len(nas) < MaxReportedList {
			nas = append(nas, NASState{
				ID:     n.ID,
				State:  oneOfOr(n.State, NASError, NASMounted, NASUnmounted, NASError),
				Detail: clip(n.Detail, MaxReportedDetail),
			})
		}
	}
	r.NAS = nas

	secrets := make([]SecretState, 0, len(r.Secrets))
	for _, s := range r.Secrets {
		if seal.ValidName(s.Name) && len(secrets) < MaxReportedList {
			secrets = append(secrets, SecretState{
				Name:  s.Name,
				State: oneOfOr(s.State, StateUnknown, SecretOK, SecretUnreadable, SecretMissing),
			})
		}
	}
	r.Secrets = secrets

	v := &r.Vectorizer
	v.State = oneOfOr(v.State, VectorizerError, VectorizerDisabled, VectorizerIdle, VectorizerRunning, VectorizerError)
	v.LastRunAt, v.LastOKAt = cleanTime(v.LastRunAt), cleanTime(v.LastOKAt)
	v.FilesIndexed, v.FilesFailed = nonNegative(v.FilesIndexed), nonNegative(v.FilesFailed)
	v.FilesSkipped, v.Chunks = nonNegative(v.FilesSkipped), nonNegative(v.Chunks)
	v.Detail = clip(v.Detail, MaxReportedDetail)

	b := &r.Backup
	b.State = oneOfOr(b.State, BackupError, BackupDisabled, BackupNoKey, BackupNever, BackupRunning, BackupOK, BackupError)
	if !reBackupKeyID.MatchString(b.KeyID) {
		b.KeyID = ""
	}
	b.LastOKAt = cleanTime(b.LastOKAt)
	b.LastSizeBytes = nonNegative(b.LastSizeBytes)
	b.Detail = clip(b.Detail, MaxReportedDetail)

	u := &r.Update
	u.CurrentVersion = clip(u.CurrentVersion, MaxReportedString)
	u.State = oneOfOr(u.State, UpdateError, UpdateIdle, UpdateDownloading, UpdateInstalling, UpdateInstalled,
		UpdateRolledBack, UpdateError)
	u.TargetVersion = clip(u.TargetVersion, MaxReportedString)
	u.Detail = clip(u.Detail, MaxReportedDetail)

	schedules := make([]ScheduleState, 0, len(r.Schedules))
	for _, s := range r.Schedules {
		if reID.MatchString(s.ID) && len(schedules) < MaxReportedList {
			schedules = append(schedules, ScheduleState{
				ID:         s.ID,
				LastRunAt:  cleanTime(s.LastRunAt),
				LastStatus: oneOfOr(s.LastStatus, StateUnknown, RunOK, RunFailed, RunSkipped, RunNever),
				NextRunAt:  cleanTime(s.NextRunAt),
			})
		}
	}
	r.Schedules = schedules
}

// FormatTime writes an instant the way Reported carries times: RFC 3339 in
// UTC with whole seconds. The zero time gives the empty string.
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func cleanTime(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return ""
	}
	return FormatTime(t)
}

func nonNegative(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}

func oneOfOr(value, fallback string, allowed ...string) string {
	for _, a := range allowed {
		if value == a {
			return value
		}
	}
	return fallback
}

// clip makes s valid UTF-8 without control characters and cuts it to max
// characters.
func clip(s string, max int) string {
	s = strings.ToValidUTF8(s, "�")
	if hasControl(s) {
		s = strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return ' '
			}
			return r
		}, s)
	}
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max])
	}
	return s
}
