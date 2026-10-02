package sim

// A synthetic stand-in for the root helper of a simulated machine, so that
// the demo can show the appliance flow end to end without Docker, NAS or
// root: the machine reports a synthetic appliance state (docs/appliance.md,
// section 6.1), validates a desired-state document it receives with the real
// validator (appliance.ParseDocument against a real catalog) and reports it
// applied at the next heartbeat, the plugins "running" as appliance.Plan
// says. Nothing is started, mounted, backed up or installed: every detail
// says "synthetic".

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/agent"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/helper"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/seal"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/version"
)

// SyntheticDetail starts every detail the synthetic helper writes.
const SyntheticDetail = "synthetic machine"

// SyntheticHelper implements agent.ApplianceHelper for a simulated machine.
// It is safe for concurrent use.
type SyntheticHelper struct {
	mu       sync.Mutex
	key      *seal.PrivateKey
	caps     appliance.Capabilities
	catalog  *appliance.Catalog
	doc      *appliance.Document
	revision int64
	status   string
	detail   string
	jobs     []string
}

var _ agent.ApplianceHelper = (*SyntheticHelper)(nil)

// NewSyntheticHelper returns a helper with the given capabilities. catalog
// may be nil: the machine then lists no catalog and refuses every document.
// The sealing key is new for every helper (a synthetic machine has no
// persistent root key).
func NewSyntheticHelper(caps appliance.Capabilities, catalog *appliance.Catalog) (*SyntheticHelper, error) {
	key, err := seal.Generate()
	if err != nil {
		return nil, err
	}
	h := &SyntheticHelper{key: key, caps: caps, catalog: catalog, status: appliance.ApplyApplied,
		detail: SyntheticDetail + ": no document applied yet"}
	if !caps.Plugins && !caps.NAS {
		h.status, h.detail = appliance.ApplyDisabled, SyntheticDetail+": plugins and NAS are switched off"
	}
	return h, nil
}

// PublicKey returns the machine's synthetic sealing key.
func (h *SyntheticHelper) PublicKey() string { return h.key.Public() }

// AppliedRevision returns the revision of the last document processed.
func (h *SyntheticHelper) AppliedRevision() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.revision
}

// Jobs returns the jobs that were asked for ("job" or "plugin_restart:<id>").
func (h *SyntheticHelper) Jobs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.jobs...)
}

// Do implements agent.ApplianceHelper.
func (h *SyntheticHelper) Do(_ context.Context, req helper.Request) (helper.Response, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch req.Action {
	case agent.ActionApplianceStatus:
		raw, err := h.statusLocked()
		if err != nil {
			return helper.Response{Code: agent.CodeFailed, Detail: SyntheticDetail + ": " + err.Error()}, nil
		}
		return helper.Response{OK: true, Detail: SyntheticDetail, Result: raw}, nil
	case agent.ActionApplianceApply:
		return h.applyLocked(req.Document), nil
	case agent.ActionApplianceRunJob:
		return h.runJobLocked(req.Job, req.Plugin), nil
	case agent.ActionUpdateInstall:
		return helper.Response{Code: agent.CodeFailed, Detail: SyntheticDetail + ": firmware is not installed on a simulated machine"}, nil
	}
	return helper.Response{Code: agent.CodeInvalid, Detail: "unknown action"}, nil
}

func (h *SyntheticHelper) applyLocked(raw []byte) helper.Response {
	if !h.caps.Plugins && !h.caps.NAS {
		h.status, h.detail = appliance.ApplyDisabled, SyntheticDetail+": plugins and NAS are switched off"
		return helper.Response{Code: agent.CodeDisabled, Detail: h.detail}
	}
	var err error
	var doc *appliance.Document
	if h.catalog == nil {
		err = errors.New("no plugin catalog is available to this simulator (--appliance-catalog)")
	} else {
		doc, err = appliance.ParseDocument(raw, h.catalog)
	}
	if err != nil {
		var head struct {
			Revision int64 `json:"revision"`
		}
		if json.Unmarshal(raw, &head) == nil && head.Revision > 0 {
			h.revision = head.Revision // processed: refused as a whole
		}
		h.status, h.detail = appliance.ApplyRejected, SyntheticDetail+": document refused, nothing changed: "+err.Error()
		return helper.Response{Code: agent.CodeInvalid, Detail: h.detail}
	}
	h.doc, h.revision = doc, doc.Revision
	h.status, h.detail = appliance.ApplyApplied, fmt.Sprintf("%s: revision %d applied in name only; nothing was started", SyntheticDetail, doc.Revision)
	result, _ := json.Marshal(map[string]any{"applied_revision": doc.Revision, "apply_status": h.status})
	return helper.Response{OK: true, Detail: h.detail, Result: result}
}

func (h *SyntheticHelper) runJobLocked(job, plugin string) helper.Response {
	allowed := false
	switch job {
	case appliance.JobVectorizeSync, appliance.JobPluginRestart:
		allowed = h.caps.Plugins
	case appliance.JobBackupRun:
		allowed = h.caps.Backup
	default:
		return helper.Response{Code: agent.CodeInvalid, Detail: "unknown job"}
	}
	if !allowed {
		return helper.Response{Code: agent.CodeDisabled, Detail: SyntheticDetail + ": this job is switched off"}
	}
	name := job
	if job == appliance.JobPluginRestart {
		if h.doc == nil || !listed(h.doc, plugin) {
			return helper.Response{Code: agent.CodeInvalid, Detail: "the plugin is not in the applied document"}
		}
		name += ":" + plugin
	}
	if len(h.jobs) < 1000 {
		h.jobs = append(h.jobs, name)
	}
	return helper.Response{OK: true, Detail: SyntheticDetail + ": job " + name + " recorded; nothing ran"}
}

func listed(doc *appliance.Document, id string) bool {
	for _, p := range doc.Plugins {
		if p.ID == id {
			return true
		}
	}
	return false
}

// statusLocked builds the appliance-status result: the contract's object
// without "schedules", plus "applied_schedules".
func (h *SyntheticHelper) statusLocked() (json.RawMessage, error) {
	rep := appliance.Reported{
		Schema: appliance.DocumentSchema, Control: appliance.ControlCloud,
		AppliedRevision: h.revision, ApplyStatus: h.status, ApplyDetail: h.detail,
		Mode: appliance.ModeVast, SealPublicKey: h.key.Public(), Capabilities: h.caps,
		Catalog: []appliance.CatalogEntry{}, Plugins: []appliance.PluginState{}, NAS: []appliance.NASState{},
		Secrets:    []appliance.SecretState{},
		Vectorizer: appliance.VectorizerState{State: appliance.VectorizerDisabled},
		Backup:     appliance.BackupState{State: appliance.BackupDisabled},
		Update:     appliance.UpdateState{CurrentVersion: version.Version, State: appliance.UpdateIdle},
	}
	if h.catalog != nil {
		rep.Catalog = h.catalog.Summary()
	}
	schedules := []appliance.Schedule{}
	if doc := h.doc; doc != nil {
		rep.Mode = doc.Mode
		for _, step := range appliance.Plan(doc, h.catalog) {
			st := appliance.PluginState{ID: step.ID, State: appliance.PluginStopped, Detail: SyntheticDetail + ": " + step.Reason, Ports: []int{}}
			if entry, ok := h.catalog.Plugin(step.ID); ok {
				st.Version = entry.Version
				for _, port := range entry.Ports {
					st.Ports = append(st.Ports, port.Port)
				}
			}
			switch {
			case step.Run && h.caps.Plugins:
				st.State, st.Detail = appliance.PluginRunning, SyntheticDetail+": not actually running"
			case step.Run:
				st.Detail = SyntheticDetail + ": ALLOW_PLUGINS is off"
			}
			if st.State == appliance.PluginRunning && st.ID == appliance.PluginVectorizer {
				rep.Vectorizer = appliance.VectorizerState{State: appliance.VectorizerIdle, Detail: SyntheticDetail + ": nothing is indexed"}
			}
			rep.Plugins = append(rep.Plugins, st)
		}
		for _, n := range doc.NAS {
			st := appliance.NASState{ID: n.ID, State: appliance.NASUnmounted, Detail: SyntheticDetail + ": ALLOW_NAS is off"}
			if h.caps.NAS {
				st.State, st.Detail = appliance.NASMounted, SyntheticDetail+": not actually mounted"
			}
			rep.NAS = append(rep.NAS, st)
		}
		for _, name := range appliance.SecretNames(doc) {
			st := appliance.SecretState{Name: name, State: appliance.SecretMissing}
			if sealed, ok := doc.Secrets[name]; ok {
				st.State = appliance.SecretUnreadable
				if plain, err := h.key.Open(name, sealed); err == nil {
					seal.Wipe(plain)
					st.State = appliance.SecretOK
				}
			}
			rep.Secrets = append(rep.Secrets, st)
		}
		if doc.Backup != nil && doc.Backup.Enabled {
			rep.Backup = appliance.BackupState{State: appliance.BackupNoKey, Detail: SyntheticDetail + ": no backup key"}
		}
		schedules = append(schedules, doc.Schedules...)
	}
	rep.Sanitize()
	raw, err := json.Marshal(rep)
	if err != nil {
		return nil, err
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	delete(out, "schedules")
	if out["applied_schedules"], err = json.Marshal(schedules); err != nil {
		return nil, err
	}
	return json.Marshal(out)
}
