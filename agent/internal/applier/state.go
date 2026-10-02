package applier

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
)

// maxStateBytes bounds state.json.
const maxStateBytes = 1 << 20

// Origins of the document being applied.
const (
	OriginCloud = "cloud"
	OriginLocal = "local"
	OriginNone  = "none"
)

// State is state.json: what the helper did and observed. It is written only
// by the helper (root, 0600) and never holds a secret, a NAS path listing or
// text of a document.
type State struct {
	Schema int `json:"schema"`

	// CloudRevision is the last cloud revision whose processing finished
	// (applied, partial, rejected or disabled); it is what the heartbeat
	// reports as applied_revision while the cloud document is in force.
	CloudRevision int64 `json:"cloud_revision"`
	// PendingRevision and PendingSHA256 identify the cloud document waiting
	// for apply-stored.
	PendingRevision int64  `json:"pending_revision,omitempty"`
	PendingSHA256   string `json:"pending_sha256,omitempty"`
	// Origin is the origin of the document last applied.
	Origin      string `json:"origin"`
	Mode        string `json:"mode"`
	ApplyStatus string `json:"apply_status"`
	ApplyDetail string `json:"apply_detail"`
	// RequestedAt is when an apply was last requested; FinishedAt when the
	// last one finished.
	RequestedAt string `json:"requested_at,omitempty"`
	FinishedAt  string `json:"finished_at,omitempty"`
	// SourceKey identifies the document (origin, content, local secrets)
	// and BootID the boot of the last finished apply: a change of either
	// makes the quick status ask for a new apply.
	SourceKey string `json:"source_key,omitempty"`
	BootID    string `json:"boot_id,omitempty"`

	Plugins           []PluginRecord `json:"plugins"`
	PluginsObservedAt string         `json:"plugins_observed_at,omitempty"`
	RefreshRequested  string         `json:"refresh_requested_at,omitempty"`
	NAS               []NASRecord    `json:"nas"`
	NetworkDetail     string         `json:"network_detail,omitempty"`

	Vectorizer           appliance.VectorizerState `json:"vectorizer"`
	VectorizerObservedAt string                    `json:"vectorizer_observed_at,omitempty"`

	Backup BackupRecord `json:"backup"`
	Update UpdateRecord `json:"update"`
	Jobs   []JobRecord  `json:"jobs"`
}

// PluginRecord is what the helper knows of one plugin.
type PluginRecord struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	// Desired: the last apply wanted it running.
	Desired bool `json:"desired"`
	// Started: HappyMining started this Compose project at some point and
	// has not taken it down since; it is stopped when it leaves the document.
	Started bool `json:"started"`
	// ApplyState and ApplyDetail are the outcome of the last apply.
	ApplyState  string `json:"apply_state"`
	ApplyDetail string `json:"apply_detail"`
	// Observed and ObservedDetail come from `docker compose ps`.
	Observed       string `json:"observed,omitempty"`
	ObservedDetail string `json:"observed_detail,omitempty"`
	Ports          []int  `json:"ports"`
	// GuardBlocked: the last apply did not start it because of the
	// foreign-container guard; the status refresh asks for a new apply when
	// no foreign container runs any more.
	GuardBlocked bool `json:"guard_blocked,omitempty"`
}

// NASRecord is what the helper knows of one NAS mount.
type NASRecord struct {
	ID string `json:"id"`
	// Mounted: HappyMining mounted it at the mount point and has not
	// unmounted it since. Only such mounts are ever unmounted.
	Mounted bool `json:"mounted"`
	// FSType is the file-system type HappyMining mounted ("cifs", "nfs").
	FSType string `json:"fstype,omitempty"`
	// Fingerprint identifies what was mounted (kind, host, share or export,
	// subpath, user, domain, access and a hash of the sealed password).
	Fingerprint string `json:"fingerprint,omitempty"`
	State       string `json:"state"`
	Detail      string `json:"detail"`
}

// BackupRecord is the backup part of state.json.
type BackupRecord struct {
	State         string `json:"state"`
	LastRunAt     string `json:"last_run_at,omitempty"`
	LastOKAt      string `json:"last_ok_at,omitempty"`
	LastSizeBytes int64  `json:"last_size_bytes"`
	Detail        string `json:"detail"`
}

// UpdateRecord is the update part of state.json.
type UpdateRecord struct {
	State         string `json:"state"`
	TargetVersion string `json:"target_version"`
	Detail        string `json:"detail"`
	// FromVersion is the version that was installed when the install began.
	FromVersion string `json:"from_version,omitempty"`
	// InstallStartedAt is when dpkg was started for TargetVersion; the guard
	// wants a heartbeat of TargetVersion after it.
	InstallStartedAt string `json:"install_started_at,omitempty"`
	InstalledAt      string `json:"installed_at,omitempty"`
	// GuardDone: the guard has decided (confirmed or rolled back).
	GuardDone bool `json:"guard_done,omitempty"`
	// GuardRequestedAt: when the quick status last started the guard
	// (its timer does not survive a reboot).
	GuardRequestedAt string `json:"guard_requested_at,omitempty"`
	// RolledBackVersion is a release that was rolled back here; it is not
	// installed again through update-install.
	RolledBackVersion string `json:"rolled_back_version,omitempty"`
}

// JobRecord is the last run of one job instance.
type JobRecord struct {
	Instance   string `json:"instance"`
	LastRunAt  string `json:"last_run_at"`
	LastStatus string `json:"last_status"`
	Detail     string `json:"detail"`
}

func newState() *State {
	return &State{
		Schema:      1,
		Origin:      OriginNone,
		Mode:        appliance.ModeVast,
		ApplyStatus: appliance.ApplyApplied,
		Plugins:     []PluginRecord{},
		NAS:         []NASRecord{},
		Jobs:        []JobRecord{},
		Vectorizer:  appliance.VectorizerState{State: appliance.VectorizerDisabled},
		Backup:      BackupRecord{State: appliance.BackupNever},
		Update:      UpdateRecord{State: appliance.UpdateIdle},
	}
}

// loadState reads state.json; a missing file is a fresh state. A damaged
// file is an error: the record of what HappyMining mounted and started must
// not silently disappear.
func (e *Env) loadState() (*State, error) {
	data, err := readFile(e.Paths.statePath(), maxStateBytes, &e.OwnerUID)
	if errors.Is(err, fs.ErrNotExist) {
		return newState(), nil
	}
	if err != nil {
		return nil, err
	}
	st := newState()
	if err := json.Unmarshal(data, st); err != nil {
		return nil, fmt.Errorf("state.json is damaged")
	}
	if st.Plugins == nil {
		st.Plugins = []PluginRecord{}
	}
	if st.NAS == nil {
		st.NAS = []NASRecord{}
	}
	if st.Jobs == nil {
		st.Jobs = []JobRecord{}
	}
	return st, nil
}

// updateState changes state.json under the short state lock: read, modify,
// write atomically. Heavy work never happens while it is held.
func (e *Env) updateState(change func(*State)) (*State, error) {
	if err := e.ensureStateDir(); err != nil {
		return nil, err
	}
	l, err := takeLock(e.Paths.state(stateLockFile))
	if err != nil {
		return nil, err
	}
	defer l.release()
	st, err := e.loadState()
	if err != nil {
		return nil, err
	}
	change(st)
	sort.Slice(st.Plugins, func(i, j int) bool { return st.Plugins[i].ID < st.Plugins[j].ID })
	sort.Slice(st.NAS, func(i, j int) bool { return st.NAS[i].ID < st.NAS[j].ID })
	sort.Slice(st.Jobs, func(i, j int) bool { return st.Jobs[i].Instance < st.Jobs[j].Instance })
	data, err := json.MarshalIndent(st, "", " ")
	if err != nil {
		return nil, err
	}
	if err := writeFile(e.Paths.StateDir, stateFile, append(data, '\n'), 0o600); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *State) plugin(id string) *PluginRecord {
	for i := range s.Plugins {
		if s.Plugins[i].ID == id {
			return &s.Plugins[i]
		}
	}
	s.Plugins = append(s.Plugins, PluginRecord{ID: id, Ports: []int{}})
	return &s.Plugins[len(s.Plugins)-1]
}

func (s *State) findPlugin(id string) (PluginRecord, bool) {
	for _, p := range s.Plugins {
		if p.ID == id {
			return p, true
		}
	}
	return PluginRecord{}, false
}

func (s *State) nas(id string) *NASRecord {
	for i := range s.NAS {
		if s.NAS[i].ID == id {
			return &s.NAS[i]
		}
	}
	s.NAS = append(s.NAS, NASRecord{ID: id})
	return &s.NAS[len(s.NAS)-1]
}

func (s *State) findNAS(id string) (NASRecord, bool) {
	for _, n := range s.NAS {
		if n.ID == id {
			return n, true
		}
	}
	return NASRecord{}, false
}

func (s *State) dropNAS(id string) {
	out := s.NAS[:0]
	for _, n := range s.NAS {
		if n.ID != id {
			out = append(out, n)
		}
	}
	s.NAS = out
}

func (s *State) dropPlugin(id string) {
	out := s.Plugins[:0]
	for _, p := range s.Plugins {
		if p.ID != id {
			out = append(out, p)
		}
	}
	s.Plugins = out
}

func (s *State) job(instance string) *JobRecord {
	for i := range s.Jobs {
		if s.Jobs[i].Instance == instance {
			return &s.Jobs[i]
		}
	}
	s.Jobs = append(s.Jobs, JobRecord{Instance: instance})
	return &s.Jobs[len(s.Jobs)-1]
}
