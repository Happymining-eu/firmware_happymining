package applier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/backup"
)

// StatusResult is the result of appliance-status: exactly the JSON of
// appliance.Reported (docs/appliance.md, 6.1) without "schedules", plus
// "applied_schedules", the schedule objects of the document in force, which
// the agent turns into the reported schedule states and removes before
// sending.
type StatusResult struct {
	// Reported holds everything but the schedule states; its Schedules is
	// always empty here.
	Reported appliance.Reported
	// AppliedSchedules are the schedules of the document in force.
	AppliedSchedules []appliance.Schedule
}

// MarshalJSON writes the Reported keys without "schedules", plus
// "applied_schedules".
func (s StatusResult) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal(s.Reported)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	delete(m, "schedules")
	sched := s.AppliedSchedules
	if sched == nil {
		sched = []appliance.Schedule{}
	}
	if m["applied_schedules"], err = json.Marshal(sched); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// UnmarshalJSON reads what MarshalJSON writes.
func (s *StatusResult) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	sched, has := m["applied_schedules"]
	delete(m, "applied_schedules")
	delete(m, "schedules")
	rest, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var rep appliance.Reported
	if err := json.Unmarshal(rest, &rep); err != nil {
		return err
	}
	s.Reported = rep
	s.AppliedSchedules = nil
	if has {
		if err := json.Unmarshal(sched, &s.AppliedSchedules); err != nil {
			return err
		}
	}
	return nil
}

// How old the plugin states may be before the quick status asks the job
// unit for fresh ones, and how often it asks.
const (
	refreshAfter = 45 * time.Second
	refreshEvery = 30 * time.Second
)

// Status is the socket action appliance-status. It reads files only (the
// state the heavy units wrote, the mount table, the profile, the catalog,
// the keys) and opens each referenced secret to tell whether it opens. When
// the plugin states are old it starts the status_refresh job; when the
// document in force, the switches or the boot changed since the last apply,
// it starts the apply unit. It never runs Docker itself.
func Status(ctx context.Context, e *Env) (StatusResult, error) {
	var res StatusResult
	if err := e.check(); err != nil {
		return res, err
	}
	st, err := e.loadState()
	if err != nil {
		return res, err
	}
	rep := appliance.Reported{
		Schema: appliance.DocumentSchema,
		Capabilities: appliance.Capabilities{
			Plugins: e.Switches.AllowPlugins, NAS: e.Switches.AllowNAS, Backup: e.Switches.AllowBackup,
			Update: e.Switches.AllowUpdate, Docker: e.hasDocker(),
		},
		ApplyStatus: st.ApplyStatus, ApplyDetail: st.ApplyDetail, Mode: st.Mode,
		Catalog: []appliance.CatalogEntry{}, Plugins: []appliance.PluginState{}, NAS: []appliance.NASState{},
		Secrets: []appliance.SecretState{}, Schedules: []appliance.ScheduleState{},
	}
	if key, err := e.sealKey(); err == nil {
		rep.SealPublicKey = key.Public()
	}
	rep.Update = appliance.UpdateState{CurrentVersion: e.Version, State: st.Update.State,
		TargetVersion: st.Update.TargetVersion, Detail: st.Update.Detail}

	eff, rerr := e.resolve()
	if rerr != nil {
		// The catalog cannot be used: nothing can be validated or applied.
		rep.Control = lenientControl(e.Paths.ProfilePath)
		rep.AppliedRevision = st.CloudRevision
		rep.ApplyStatus, rep.ApplyDetail = appliance.ApplyRejected, clipText(rerr.Error(), 400)
		rep.Backup = e.backupState(nil, st)
		rep.Vectorizer = appliance.VectorizerState{State: appliance.VectorizerDisabled}
		rep.Sanitize()
		res.Reported = rep
		return res, nil
	}
	rep.Control = eff.Control
	rep.Catalog = eff.Catalog.Summary()
	rep.AppliedRevision = reportedRevision(st, eff.Origin)
	doc := eff.Doc
	if doc == nil {
		doc = emptyVast()
	}
	switch {
	case eff.Problem != "":
		rep.ApplyStatus, rep.ApplyDetail = appliance.ApplyRejected, eff.Problem
	case !e.applyAllowed():
		rep.ApplyStatus = appliance.ApplyDisabled
		rep.ApplyDetail = "applying is disabled in helper.conf (ALLOW_PLUGINS and ALLOW_NAS are off)"
	}
	rep.Plugins = pluginStates(doc, eff.Catalog, st)
	mounts, merr := e.readMountInfo()
	rep.NAS = nasStates(doc, st, mounts, merr, e.Paths)
	op := e.newOpener(eff.Secrets)
	rep.Secrets = op.secretStates(doc, eff.Catalog)
	rep.Vectorizer = vectorizerState(doc, eff.Catalog, st)
	rep.Backup = e.backupState(doc, st)
	res.AppliedSchedules = append([]appliance.Schedule{}, doc.Schedules...)
	rep.Sanitize()
	res.Reported = rep

	e.maybeTrigger(ctx, eff, st)
	return res, nil
}

// maybeTrigger starts the apply or the refresh unit when needed.
func (e *Env) maybeTrigger(ctx context.Context, eff *effective, st *State) {
	now := e.now()
	if eff.Problem == "" && e.applyNeeded(st) {
		changed := eff.SourceKey+e.switchKey() != st.SourceKey || e.bootID() != st.BootID
		pending := st.ApplyStatus == appliance.ApplyPending
		stale := pending && olderThan(st.RequestedAt, now, pendingRetry)
		if (changed && !pending) || stale {
			e.audit("appliance-status: the document in force, the switches or the boot changed; requesting an apply")
			e.requestApply(ctx)
		}
	}
	// The guard timer does not survive a reboot: start the guard when an
	// installation was not decided long after it.
	if u := st.Update; u.State == appliance.UpdateInstalled && !u.GuardDone && u.InstalledAt != "" &&
		olderThan(u.InstalledAt, now, guardDelay+2*time.Minute) && olderThan(u.GuardRequestedAt, now, guardDelay) {
		if _, err := e.updateState(func(s *State) { s.Update.GuardRequestedAt = appliance.FormatTime(now) }); err == nil {
			_ = e.startUnit(ctx, UnitUpdateGuard)
		}
	}
	if e.Switches.AllowPlugins && olderThan(st.PluginsObservedAt, now, refreshAfter) &&
		olderThan(st.RefreshRequested, now, refreshEvery) && hasStartedPlugin(st) {
		if _, err := e.updateState(func(s *State) { s.RefreshRequested = appliance.FormatTime(now) }); err == nil {
			_ = e.startUnit(ctx, JobUnit(JobStatusRefresh))
		}
	}
}

func hasStartedPlugin(st *State) bool {
	for _, p := range st.Plugins {
		if p.Started || p.Desired {
			return true
		}
	}
	return false
}

// olderThan reports whether the RFC 3339 time t is empty, unreadable or
// more than d before now.
func olderThan(t string, now time.Time, d time.Duration) bool {
	if t == "" {
		return true
	}
	parsed, err := time.Parse(time.RFC3339, t)
	if err != nil {
		return true
	}
	return now.Sub(parsed) > d
}

// lenientControl reads "control" from a profile that cannot be validated
// (the catalog is unusable): a present file that does not say "cloud" is
// taken as local, which refuses cloud documents.
func lenientControl(path string) string {
	data, err := readFile(path, appliance.MaxDocumentBytes, nil)
	if errors.Is(err, errNotExist) {
		return appliance.ControlCloud
	}
	var probe struct {
		Control string `json:"control"`
	}
	if err != nil || json.Unmarshal(data, &probe) != nil || probe.Control != appliance.ControlCloud {
		return appliance.ControlLocal
	}
	return appliance.ControlCloud
}

// pluginStates reports the document's plugins in plan order, and the ones
// HappyMining started that left the document and are not stopped yet.
func pluginStates(doc *appliance.Document, cat *appliance.Catalog, st *State) []appliance.PluginState {
	out := []appliance.PluginState{}
	listed := map[string]bool{}
	for _, step := range appliance.Plan(doc, cat) {
		listed[step.ID] = true
		entry, ok := cat.Plugin(step.ID)
		rec, has := st.findPlugin(step.ID)
		ps := appliance.PluginState{ID: step.ID, Ports: catalogPorts(entry)}
		if ok {
			ps.Version = entry.Version
		}
		switch {
		case !ok:
			ps.State, ps.Detail = appliance.PluginNotInCatalog, "not in the installed catalog"
		case !has || rec.ApplyState == "":
			ps.State, ps.Detail = appliance.PluginStopped, "not applied yet"
		default:
			ps.State, ps.Detail = reportedPluginState(rec)
		}
		out = append(out, ps)
	}
	for _, rec := range st.Plugins {
		if listed[rec.ID] || !rec.Started {
			continue
		}
		state, detail := rec.Observed, "removed from the document; being stopped"
		if state == "" {
			state = appliance.PluginRunning
		}
		out = append(out, appliance.PluginState{ID: rec.ID, State: state, Detail: detail, Version: rec.Version, Ports: rec.Ports})
	}
	return out
}

// reportedPluginState combines the outcome of the last apply with what was
// observed since.
func reportedPluginState(rec PluginRecord) (string, string) {
	switch rec.ApplyState {
	case appliance.PluginStarting, appliance.PluginRunning:
		if rec.Observed != "" {
			return rec.Observed, rec.ObservedDetail
		}
		return appliance.PluginStarting, ""
	case appliance.PluginError:
		if rec.Started && rec.Observed != "" && rec.Observed != appliance.PluginRunning && rec.Observed != appliance.PluginStarting {
			return appliance.PluginError, joinDetails([]string{rec.ApplyDetail, rec.ObservedDetail}, 450)
		}
		return appliance.PluginError, rec.ApplyDetail
	default:
		if rec.Observed == appliance.PluginRunning {
			return appliance.PluginRunning, "running although it should not: " + rec.ApplyDetail
		}
		return rec.ApplyState, rec.ApplyDetail
	}
}

// vectorizerState is the last observed status.json while the vectorizer
// runs, "disabled" when the document does not run it.
func vectorizerState(doc *appliance.Document, cat *appliance.Catalog, st *State) appliance.VectorizerState {
	runs := false
	for _, step := range appliance.Plan(doc, cat) {
		if step.ID == vectorizerPlugin && step.Run {
			runs = true
		}
	}
	if !runs {
		v := st.Vectorizer
		v.State, v.Detail = appliance.VectorizerDisabled, ""
		return v
	}
	v := st.Vectorizer
	if v.State == "" || v.State == appliance.VectorizerDisabled {
		v.State = appliance.VectorizerIdle
	}
	return v
}

// backupState is the reported backup state.
func (e *Env) backupState(doc *appliance.Document, st *State) appliance.BackupState {
	bs := appliance.BackupState{State: st.Backup.State, LastOKAt: st.Backup.LastOKAt,
		LastSizeBytes: st.Backup.LastSizeBytes, Detail: st.Backup.Detail}
	key, err := backup.LoadKey(e.Paths.backupKeyPath(), e.OwnerUID)
	switch {
	case err == nil:
		bs.KeyPresent, bs.KeyID = true, backup.KeyID(key)
	case !errors.Is(err, backup.ErrNoKey):
		bs.Detail = "the backup key file cannot be used"
	}
	switch {
	case doc == nil || doc.Backup == nil || !doc.Backup.Enabled:
		bs.State = appliance.BackupDisabled
	case !e.Switches.AllowBackup:
		bs.State, bs.Detail = appliance.BackupDisabled, "backups are disabled in helper.conf (ALLOW_BACKUP)"
	case !bs.KeyPresent:
		bs.State = appliance.BackupNoKey
	case bs.State == "":
		bs.State = appliance.BackupNever
	}
	return bs
}

// refreshPlugins asks Compose for the containers of every plugin HappyMining
// started or wants running, reads the vectorizer's status.json and records
// both. It also asks for a new apply when a GPU plugin was blocked by the
// foreign-container guard and no foreign container runs any more. Heavy
// units only.
func (e *Env) refreshPlugins(ctx context.Context) {
	if !e.Switches.AllowPlugins || !e.hasDocker() {
		return
	}
	st, err := e.loadState()
	if err != nil {
		return
	}
	type obs struct{ state, detail string }
	seen := map[string]obs{}
	guardBlocked := false
	for _, rec := range st.Plugins {
		if !ValidID(rec.ID) || (!rec.Started && !rec.Desired) {
			continue
		}
		guardBlocked = guardBlocked || rec.GuardBlocked
		state, detail, err := e.projectState(ctx, rec.ID)
		if err != nil {
			state, detail = appliance.PluginError, clipText(err.Error(), 200)
		}
		seen[rec.ID] = obs{state, detail}
	}
	var vec *appliance.VectorizerState
	if o, ok := seen[vectorizerPlugin]; ok && (o.state == appliance.PluginRunning || o.state == appliance.PluginStarting) {
		v := e.readVectorizerStatus(ctx)
		vec = &v
	}
	now := appliance.FormatTime(e.now())
	_, _ = e.updateState(func(s *State) {
		for id, o := range seen {
			r := s.plugin(id)
			r.Observed, r.ObservedDetail = o.state, o.detail
		}
		s.PluginsObservedAt = now
		if vec != nil {
			s.Vectorizer = *vec
			s.VectorizerObservedAt = now
		}
	})
	if guardBlocked {
		if n, err := e.foreignContainers(ctx); err == nil && n == 0 {
			e.audit("status refresh: no foreign container runs any more; requesting an apply for the GPU plugins")
			e.requestApply(ctx)
		}
	}
}

// maxVectorizerStatus bounds status.json.
const maxVectorizerStatus = 64 * 1024

// readVectorizerStatus reads status.json from the vectorizer's state volume,
// without following a link, bounded, as untrusted input (the container
// writes it).
func (e *Env) readVectorizerStatus(ctx context.Context) appliance.VectorizerState {
	fail := func(detail string) appliance.VectorizerState {
		return appliance.VectorizerState{State: appliance.VectorizerError, Detail: detail}
	}
	dir, ok, err := e.volumePath(ctx, vectorizerPlugin, "state")
	if err != nil || !ok {
		return fail("the vectorizer's state volume cannot be found")
	}
	data, err := readFile(filepath.Join(dir, "status.json"), maxVectorizerStatus, nil)
	if errors.Is(err, errNotExist) {
		return appliance.VectorizerState{State: appliance.VectorizerIdle}
	}
	if err != nil {
		return fail("the vectorizer's status cannot be read")
	}
	var raw struct {
		State        string `json:"state"`
		LastRunAt    string `json:"last_run_at"`
		LastOKAt     string `json:"last_ok_at"`
		FilesIndexed int64  `json:"files_indexed"`
		FilesFailed  int64  `json:"files_failed"`
		FilesSkipped int64  `json:"files_skipped"`
		Chunks       int64  `json:"chunks"`
		Detail       string `json:"detail"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&raw); err != nil {
		return fail("the vectorizer's status cannot be read")
	}
	v := appliance.VectorizerState{State: raw.State, LastRunAt: raw.LastRunAt, LastOKAt: raw.LastOKAt,
		FilesIndexed: raw.FilesIndexed, FilesFailed: raw.FilesFailed, FilesSkipped: raw.FilesSkipped,
		Chunks: raw.Chunks, Detail: clipText(raw.Detail, appliance.MaxReportedDetail)}
	switch v.State {
	case appliance.VectorizerIdle, appliance.VectorizerRunning, appliance.VectorizerError:
	default:
		v.State, v.Detail = appliance.VectorizerError, "the vectorizer reported an unknown state"
	}
	return v
}
