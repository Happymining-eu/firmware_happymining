package applier

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
)

// Response codes shared with the socket helper.
const (
	CodeInvalid           = "invalid"
	CodeDisabled          = "disabled"
	CodeFailed            = "failed"
	CodeLocallyControlled = "locally_controlled"
	CodeBusy              = "busy"
)

// Outcome is what a quick action answers: OK, or a code and a detail, and
// an optional result object.
type Outcome struct {
	OK     bool
	Code   string
	Detail string
	Result any
}

func refused(code, detail string) Outcome { return Outcome{Code: code, Detail: detail} }

// ApplyResult is the result of appliance-apply.
type ApplyResult struct {
	AppliedRevision int64  `json:"applied_revision"`
	ApplyStatus     string `json:"apply_status"`
}

// pendingRetry: an apply requested this long ago that has not finished is
// requested again (the unit may have been killed).
const pendingRetry = 10 * time.Minute

// switchKey makes the switches part of the source key, so that changing
// helper.conf leads to a new apply.
func (e *Env) switchKey() string {
	b := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	s := e.Switches
	return "|sw=" + b(s.AllowPlugins) + b(s.AllowNAS) + b(s.AllowUnpinnedImages) + b(s.AllowForeignContainers)
}

func (e *Env) applyAllowed() bool { return e.Switches.AllowPlugins || e.Switches.AllowNAS }

// applyNeeded: an apply has something to do. With both switches off it can
// still have to stop plugins HappyMining started while ALLOW_PLUGINS was on
// and that the document no longer runs (vast mode above all): stopping needs
// no switch, starting does (applyPlugins).
func (e *Env) applyNeeded(st *State) bool {
	if e.applyAllowed() {
		return true
	}
	for _, rec := range st.Plugins {
		if rec.Started {
			return true
		}
	}
	return false
}

// startUnit asks systemd to start a heavy unit without waiting for it.
func (e *Env) startUnit(ctx context.Context, unit string) error {
	res := e.run(ctx, timeoutSystemctl, SystemctlPath, "start", "--no-block", unit)
	if !res.ok {
		return fmt.Errorf("systemctl start %s failed: %s", unit, res.describe(nil))
	}
	return nil
}

// QuickApply is the socket action appliance-apply: validate the cloud
// document against the installed catalog, refuse it under local control,
// persist it and start happymining-appliance-apply.service. It runs no
// Docker, mount or dpkg command.
func QuickApply(ctx context.Context, e *Env, raw json.RawMessage) Outcome {
	if err := e.check(); err != nil {
		return refused(CodeFailed, err.Error())
	}
	cat, err := e.loadCatalog()
	if err != nil {
		return refused(CodeFailed, "the installed plugin catalog cannot be used: "+clipText(err.Error(), 300))
	}
	prof, err := appliance.LoadProfile(e.Paths.ProfilePath, e.OwnerUID, cat)
	if err != nil {
		return refused(CodeLocallyControlled, "the local profile "+e.Paths.ProfilePath+
			" cannot be used; cloud documents are refused until it is fixed or removed")
	}
	if prof.Control == appliance.ControlLocal {
		return refused(CodeLocallyControlled, "this machine follows its local profile (control: local); cloud documents are ignored")
	}
	compact, cerr := compactJSON(raw)
	doc, err := appliance.ParseDocument(raw, cat)
	if cerr != nil || err != nil {
		detail := "the document is not valid JSON"
		if err != nil {
			detail = "document refused: " + clipText(err.Error(), 400)
		}
		rev := revisionOf(raw)
		if rev > 0 {
			st, uerr := e.updateState(func(st *State) {
				st.CloudRevision, st.ApplyStatus, st.ApplyDetail = rev, appliance.ApplyRejected, detail
				st.FinishedAt = appliance.FormatTime(e.now())
				// The document in force is unchanged; only the reported
				// outcome of this revision is.
			})
			if uerr == nil {
				return Outcome{Code: CodeInvalid, Detail: detail,
					Result: ApplyResult{AppliedRevision: st.CloudRevision, ApplyStatus: st.ApplyStatus}}
			}
		}
		return refused(CodeInvalid, detail)
	}
	rev, sha := doc.Revision, sha256Hex(compact)
	st, err := e.loadState()
	if err != nil {
		return refused(CodeFailed, err.Error())
	}
	boot := e.bootID()
	sourceKey := OriginCloud + ":" + sha + e.switchKey()
	if st.Origin == OriginCloud && st.CloudRevision == rev && st.SourceKey == sourceKey && st.BootID == boot &&
		st.ApplyStatus != appliance.ApplyPending && st.PendingSHA256 == "" {
		e.audit("appliance-apply revision=%d: already applied (%s)", rev, st.ApplyStatus)
		return Outcome{OK: true, Detail: "revision already applied",
			Result: ApplyResult{AppliedRevision: st.CloudRevision, ApplyStatus: st.ApplyStatus}}
	}
	if !(st.PendingSHA256 == sha && st.ApplyStatus == appliance.ApplyPending) {
		if err := e.saveApplied(&Applied{Origin: OriginCloud, Revision: rev, SHA256: sha,
			Received: appliance.FormatTime(e.now()), Document: compact}); err != nil {
			return refused(CodeFailed, "the document cannot be stored: "+err.Error())
		}
	}
	if !e.applyNeeded(st) {
		detail := "applying is disabled in helper.conf (ALLOW_PLUGINS and ALLOW_NAS are off)"
		st, err = e.updateState(func(st *State) {
			st.CloudRevision, st.ApplyStatus, st.ApplyDetail = rev, appliance.ApplyDisabled, detail
			st.PendingRevision, st.PendingSHA256, st.SourceKey = 0, "", ""
			st.Origin, st.Mode = OriginCloud, doc.Mode
			st.FinishedAt = appliance.FormatTime(e.now())
		})
		if err != nil {
			return refused(CodeFailed, err.Error())
		}
		e.audit("appliance-apply revision=%d: stored, applying disabled", rev)
		return Outcome{Code: CodeDisabled, Detail: detail,
			Result: ApplyResult{AppliedRevision: st.CloudRevision, ApplyStatus: st.ApplyStatus}}
	}
	st, err = e.updateState(func(st *State) {
		st.PendingRevision, st.PendingSHA256 = rev, sha
		st.ApplyStatus, st.ApplyDetail = appliance.ApplyPending, ""
		st.RequestedAt = appliance.FormatTime(e.now())
	})
	if err != nil {
		return refused(CodeFailed, err.Error())
	}
	if err := e.startUnit(ctx, UnitApply); err != nil {
		return refused(CodeFailed, err.Error())
	}
	e.audit("appliance-apply revision=%d: stored, %s started", rev, UnitApply)
	return Outcome{OK: true, Detail: "document stored; applying",
		Result: ApplyResult{AppliedRevision: st.CloudRevision, ApplyStatus: appliance.ApplyPending}}
}

// requestApply marks an apply as pending and starts the unit (used by the
// quick status when the document in force or the boot changed).
func (e *Env) requestApply(ctx context.Context) {
	if _, err := e.updateState(func(st *State) {
		st.ApplyStatus = appliance.ApplyPending
		st.RequestedAt = appliance.FormatTime(e.now())
	}); err != nil {
		return
	}
	if err := e.startUnit(ctx, UnitApply); err != nil {
		e.audit("apply request failed: %v", err)
	}
}

// ApplyStored is `hm-helper apply-stored`, run by
// happymining-appliance-apply.service: apply the document in force (see
// resolve) under the appliance lock. A failing item does not stop the
// others. When a newer document arrived meanwhile, it is applied in turn.
func ApplyStored(ctx context.Context, e *Env) error {
	if err := e.check(); err != nil {
		return err
	}
	if err := e.ensureStateDir(); err != nil {
		return err
	}
	l, err := takeLock(e.Paths.state(lockFile))
	if err != nil {
		return err
	}
	defer l.release()
	for round := 0; round < 5; round++ {
		key, err := e.applyOnce(ctx)
		if err != nil {
			return err
		}
		eff, rerr := e.resolve()
		if rerr != nil || eff.Problem != "" || eff.SourceKey+e.switchKey() == key {
			break
		}
		e.audit("apply-stored: the document changed while it was applied; applying again")
	}
	// Report the containers as they are now.
	e.refreshPlugins(ctx)
	return nil
}

// applyOnce applies the document in force once and returns its source key.
func (e *Env) applyOnce(ctx context.Context) (string, error) {
	started := e.now()
	boot := e.bootID()
	eff, err := e.resolve()
	if err != nil {
		detail := clipText(err.Error(), 400)
		_, uerr := e.updateState(func(st *State) {
			if st.PendingRevision > 0 {
				st.CloudRevision = st.PendingRevision
			}
			st.PendingRevision, st.PendingSHA256 = 0, ""
			st.ApplyStatus, st.ApplyDetail = appliance.ApplyRejected, detail
			st.FinishedAt = appliance.FormatTime(e.now())
		})
		return "", uerr
	}
	key := eff.SourceKey + e.switchKey()
	finish := func(status, detail string) error {
		_, err := e.updateState(func(st *State) {
			if eff.Origin == OriginCloud {
				st.CloudRevision = eff.Revision
			}
			if st.PendingSHA256 == "" || OriginCloud+":"+st.PendingSHA256 == eff.SourceKey {
				st.PendingRevision, st.PendingSHA256 = 0, ""
			}
			st.Origin = eff.Origin
			if eff.Doc != nil {
				st.Mode = eff.Doc.Mode
			}
			st.ApplyStatus, st.ApplyDetail = status, clipText(detail, appliance.MaxReportedDetail)
			st.FinishedAt = appliance.FormatTime(e.now())
			st.SourceKey, st.BootID = key, boot
		})
		e.audit("apply-stored: origin=%s revision=%d status=%s (%s)", eff.Origin, eff.Revision, status,
			e.now().Sub(started).Round(time.Second))
		return err
	}
	if eff.Problem != "" {
		return key, finish(appliance.ApplyRejected, eff.Problem)
	}
	e.audit("apply-stored: applying origin=%s revision=%d mode=%s", eff.Origin, eff.Revision, eff.Doc.Mode)
	op := e.newScrubbingOpener(eff.Secrets)

	var failed, disabled []string
	var blocked []string
	collect := func(p pluginOutcome) {
		failed = append(failed, p.Failed...)
		blocked = append(blocked, p.Blocked...)
		if p.Disabled {
			disabled = append(disabled, "starting plugins is disabled (ALLOW_PLUGINS)")
		}
	}
	// 1. Vast mode: every plugin stops before anything else happens.
	vast := eff.Doc.Mode == appliance.ModeVast
	if vast {
		collect(e.applyPlugins(ctx, eff, op))
	}
	// 2. NAS. What uses the shares (the vectorizer) is stopped before the
	// first mount or unmount; the plugin step starts it again, in a new
	// mount namespace that sees the new mounts.
	nas := e.applyNAS(ctx, eff.Doc, op, func() { e.stopVectorizerForNAS(ctx) })
	failed = append(failed, nas.Failed...)
	if nas.Disabled {
		disabled = append(disabled, "mounting NAS entries is disabled (ALLOW_NAS)")
	}
	// 3 and 4. The network and the plugins.
	if !vast {
		collect(e.applyPlugins(ctx, eff, op))
	}

	switch {
	case len(failed) > 0 || len(blocked) > 0:
		parts := failed
		if len(blocked) > 0 {
			parts = append(parts, "blocked: "+strings.Join(blocked, ", "))
		}
		return key, finish(appliance.ApplyPartial, joinDetails(parts, appliance.MaxReportedDetail))
	case len(disabled) > 0:
		return key, finish(appliance.ApplyDisabled, joinDetails(disabled, appliance.MaxReportedDetail))
	}
	return key, finish(appliance.ApplyApplied, "")
}

// stopVectorizerForNAS stops the vectorizer (if HappyMining started it)
// before NAS mounts change, so that no share is unmounted under it.
func (e *Env) stopVectorizerForNAS(ctx context.Context) {
	if !e.Switches.AllowPlugins || !e.hasDocker() {
		return
	}
	st, err := e.loadState()
	if err != nil {
		return
	}
	if rec, ok := st.findPlugin(vectorizerPlugin); ok && rec.Started {
		e.docker(ctx, timeoutComposeDown, argvComposeStop(vectorizerPlugin)...)
	}
}
