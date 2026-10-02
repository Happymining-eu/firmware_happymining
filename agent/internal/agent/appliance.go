package agent

// The appliance part of the agent (docs/appliance.md, sections 6 and 9, and the
// helper interface): before each heartbeat the agent asks the root helper for
// the appliance state, adds its own schedule and update state, and sends the
// result as the heartbeat's "appliance" object. A document in the response is
// handed to the helper, which validates and applies it. The agent never
// interprets the document beyond its size and revision, never opens a secret
// and never runs anything itself except the update check and download.
//
// Nothing here may hold up telemetry: every helper call is bounded, and a
// helper that does not answer is reported as such.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/helper"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/version"
)

// ApplianceHelper reaches the root helper for the appliance actions. It is
// implemented by *helper.Client in production, by fakes in tests and by a
// synthetic helper in the simulator.
type ApplianceHelper interface {
	Do(ctx context.Context, req helper.Request) (helper.Response, error)
}

// Helper actions and response codes of the appliance interface. They are
// spelled out here, as the interface defines them, so that the agent does not
// depend on how the helper package names them.
const (
	ActionApplianceStatus = "appliance-status"
	ActionApplianceApply  = "appliance-apply"
	ActionApplianceRunJob = "appliance-run-job"
	ActionUpdateInstall   = "update-install"

	CodeInvalid           = "invalid"
	CodeDisabled          = "disabled"
	CodeFailed            = "failed"
	CodeUnauthorized      = "unauthorized"
	CodeLocallyControlled = "locally_controlled"
	CodeBusy              = "busy"
)

// Bounds of the appliance exchange.
const (
	// DefaultApplianceStatusTimeout bounds the appliance-status call made
	// before each heartbeat.
	DefaultApplianceStatusTimeout = 10 * time.Second
	// applianceCallTimeout bounds the other quick helper calls.
	applianceCallTimeout = 30 * time.Second
	// maxApplianceReportBytes bounds the encoded appliance object, so that a
	// heartbeat always fits the 256 KiB request limit with its samples.
	maxApplianceReportBytes = 64 * 1024
	// applyRetryMin and applyRetryMax bound the delay before a document whose
	// hand-off failed is offered to the helper again.
	applyRetryMin = time.Minute
	applyRetryMax = 30 * time.Minute
)

// helperStatus is the result of appliance-status: the contract's section 6.1
// object without "schedules", plus the schedule objects of the applied
// document, which the agent runs and removes before sending.
type helperStatus struct {
	appliance.Reported
	AppliedSchedules []json.RawMessage `json:"applied_schedules"`
}

// applianceState is the agent's appliance bookkeeping. It is only touched by
// the agent loop goroutine.
type applianceState struct {
	status    *helperStatus
	statusAt  time.Time
	statusErr string

	// handed is the last document revision the helper accepted from this
	// agent run; refused is the last one it refused for good (invalid or
	// locally controlled). Neither is offered again.
	handed, refused int64
	// retryRevision is a revision whose hand-off failed and may be offered
	// again at retryAt; retryDelay grows with each failure.
	retryRevision int64
	retryAt       time.Time
	retryDelay    time.Duration
	// warned limits repeated log lines about the same condition.
	warned map[string]bool
}

func (a *Agent) warnOnce(key, msg string, args ...any) {
	if a.appl.warned == nil {
		a.appl.warned = map[string]bool{}
	}
	if a.appl.warned[key] || len(a.appl.warned) > 64 {
		return
	}
	a.appl.warned[key] = true
	a.log.Warn(msg, args...)
}

// helperDo calls the appliance helper with a bound on time.
func (a *Agent) helperDo(ctx context.Context, timeout time.Duration, req helper.Request) (helper.Response, error) {
	if a.o.Appliance == nil {
		return helper.Response{}, errors.New("the privileged helper is not available in this build")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return a.o.Appliance.Do(ctx, req)
}

// refreshApplianceStatus asks the helper for the appliance state. On success
// the applied schedules replace the agent's schedule list.
func (a *Agent) refreshApplianceStatus(ctx context.Context) {
	a.appl.statusAt = a.now()
	resp, err := a.helperDo(ctx, a.o.ApplianceStatusTimeout, helper.Request{Action: ActionApplianceStatus})
	switch {
	case err != nil:
		a.applianceStatusFailed("the privileged helper is not reachable: " + err.Error())
		return
	case !resp.OK:
		a.applianceStatusFailed(fmt.Sprintf("the privileged helper refused appliance-status (%s): %s",
			protocol.Truncate(resp.Code, 40), resp.Detail))
		return
	}
	var st helperStatus
	if err := json.Unmarshal(resp.Result, &st); err != nil || len(bytes.TrimSpace(resp.Result)) == 0 {
		a.applianceStatusFailed("the privileged helper sent an appliance status that is not the expected JSON object")
		return
	}
	if a.appl.statusErr != "" {
		a.log.Info("the privileged helper answers appliance-status again")
	}
	a.appl.status, a.appl.statusErr = &st, ""
	a.sched.setSchedules(a.parseSchedules(st.AppliedSchedules), a.now())
}

func (a *Agent) applianceStatusFailed(reason string) {
	reason = protocol.Truncate(a.o.Redactor.String(reason), appliance.MaxReportedDetail)
	if reason != a.appl.statusErr {
		a.log.Warn("appliance state unavailable; a minimal appliance object is reported", "reason", reason)
	}
	// The schedules of the last known state are kept: the helper may be back
	// in a moment, and what ran is still worth reporting.
	a.appl.status, a.appl.statusErr = nil, reason
}

var reID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// parseSchedules decodes the helper's schedule objects strictly and keeps the
// well-formed ones (the helper validated them already; the agent trusts none
// of it). At most appliance.MaxSchedules are kept.
func (a *Agent) parseSchedules(raw []json.RawMessage) []appliance.Schedule {
	var out []appliance.Schedule
	seen := map[string]bool{}
	for _, item := range raw {
		s, err := parseSchedule(item)
		if err == nil && seen[s.ID] {
			err = errors.New("duplicate schedule id")
		}
		if err != nil {
			a.warnOnce("schedule:"+err.Error(), "a schedule of the applied document is ignored", "reason", err.Error())
			continue
		}
		if len(out) >= appliance.MaxSchedules {
			a.warnOnce("schedules:too-many", "more schedules than the contract allows; the rest is ignored")
			break
		}
		seen[s.ID] = true
		out = append(out, s)
	}
	return out
}

func parseSchedule(raw json.RawMessage) (appliance.Schedule, error) {
	var s appliance.Schedule
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, errors.New("not a schedule object")
	}
	if dec.More() {
		return s, errors.New("trailing data")
	}
	if !reID.MatchString(s.ID) {
		return s, errors.New("invalid schedule id")
	}
	switch s.Job {
	case appliance.JobVectorizeSync, appliance.JobBackupRun, appliance.JobUpdateCheck:
		if s.Plugin != "" {
			return s, errors.New("only plugin_restart names a plugin")
		}
	case appliance.JobPluginRestart:
		if !reID.MatchString(s.Plugin) {
			return s, errors.New("plugin_restart needs a plugin id")
		}
	default:
		return s, errors.New("unknown job")
	}
	if err := s.Spec().Validate(); err != nil {
		return s, err
	}
	return s, nil
}

// minimalReport is what the agent says when the helper cannot tell: nothing
// is known, nothing can be done, and why.
func (a *Agent) minimalReport(reason string) appliance.Reported {
	return appliance.Reported{
		Schema:      appliance.DocumentSchema,
		Control:     appliance.StateUnknown,
		ApplyStatus: appliance.ApplyDisabled,
		ApplyDetail: reason,
		Mode:        appliance.StateUnknown,
		Vectorizer:  appliance.VectorizerState{State: appliance.VectorizerDisabled},
		Backup:      appliance.BackupState{State: appliance.BackupDisabled},
		Update:      appliance.UpdateState{CurrentVersion: version.Version, State: appliance.UpdateIdle},
	}
}

// applianceReport returns the encoded appliance object for the next heartbeat,
// or nil when the agent has no helper to ask (it then sends nothing, as agent
// 0.1.0 did). It refreshes the helper state first.
func (a *Agent) applianceReport(ctx context.Context) json.RawMessage {
	if a.o.Appliance == nil {
		return nil
	}
	a.refreshApplianceStatus(ctx)
	var rep appliance.Reported
	if a.appl.status != nil {
		rep = a.appl.status.Reported
	} else {
		rep = a.minimalReport(a.appl.statusErr)
	}
	rep.Schedules = a.sched.report()
	rep.Update = a.upd.merge(rep.Update, a.now())
	a.redactReport(&rep)
	rep.Sanitize()
	raw, err := json.Marshal(rep)
	if err == nil && len(raw) > maxApplianceReportBytes {
		// Free text is what can be long: drop it before anything else.
		for i := range rep.Plugins {
			rep.Plugins[i].Detail = ""
		}
		for i := range rep.NAS {
			rep.NAS[i].Detail = ""
		}
		rep.ApplyDetail = "the appliance report was too large; details were left out"
		raw, err = json.Marshal(rep)
	}
	if err != nil || len(raw) > maxApplianceReportBytes {
		small := a.minimalReport("the appliance report was too large to send")
		small.Sanitize()
		raw, _ = json.Marshal(small)
	}
	return raw
}

// redactReport removes known secrets (the device credential among them) from
// every free-text field before the report leaves the machine.
func (a *Agent) redactReport(rep *appliance.Reported) {
	r := a.o.Redactor
	rep.ApplyDetail = r.String(rep.ApplyDetail)
	for i := range rep.Plugins {
		rep.Plugins[i].Detail = r.String(rep.Plugins[i].Detail)
	}
	for i := range rep.NAS {
		rep.NAS[i].Detail = r.String(rep.NAS[i].Detail)
	}
	rep.Vectorizer.Detail = r.String(rep.Vectorizer.Detail)
	rep.Backup.Detail = r.String(rep.Backup.Detail)
	rep.Update.Detail = r.String(rep.Update.Detail)
}

// capabilities returns what the helper last said it may do (all false when
// it did not say).
func (a *Agent) capabilities() appliance.Capabilities {
	if a.appl.status == nil {
		return appliance.Capabilities{}
	}
	return a.appl.status.Capabilities
}

// onApplianceResponse hands a document of a heartbeat response to the helper,
// once per revision.
func (a *Agent) onApplianceResponse(ctx context.Context, resp *protocol.ApplianceResponse) {
	if a.o.Appliance == nil || resp == nil || len(resp.Document) == 0 {
		return
	}
	rev := resp.Revision
	if rev < 1 || rev == a.appl.handed || rev == a.appl.refused {
		return
	}
	if rev == a.appl.retryRevision && a.now().Before(a.appl.retryAt) {
		return
	}
	if a.appl.status == nil || a.appl.status.Control != appliance.ControlCloud {
		a.warnOnce(fmt.Sprintf("document-not-cloud:%d", rev),
			"a desired-state document arrived but the helper does not report cloud control; it is not handed over",
			"revision", rev)
		return
	}
	var doc bytes.Buffer
	if err := json.Compact(&doc, resp.Document); err != nil {
		a.refuseDocument(rev, "the document is not valid JSON")
		return
	}
	if doc.Len() > appliance.MaxDocumentBytes {
		a.refuseDocument(rev, fmt.Sprintf("the document is %d bytes, more than the %d the contract allows", doc.Len(), appliance.MaxDocumentBytes))
		return
	}
	var head struct {
		Revision json.Number `json:"revision"`
	}
	dec := json.NewDecoder(bytes.NewReader(doc.Bytes()))
	dec.UseNumber()
	if doc.Bytes()[0] != '{' || dec.Decode(&head) != nil || head.Revision.String() != fmt.Sprint(rev) {
		a.refuseDocument(rev, "the document is not an object carrying the revision of the response")
		return
	}
	res, err := a.helperDo(ctx, applianceCallTimeout, helper.Request{Action: ActionApplianceApply, Document: doc.Bytes()})
	switch {
	case err == nil && res.OK:
		a.appl.handed, a.appl.retryRevision, a.appl.retryDelay = rev, 0, 0
		a.appl.statusAt = time.Time{} // report the new state at the next opportunity
		a.log.Info("desired-state document handed to the helper", "revision", rev,
			"detail", protocol.Truncate(a.o.Redactor.String(res.Detail), 300))
	case err == nil && (res.Code == CodeInvalid || res.Code == CodeLocallyControlled):
		a.refuseDocument(rev, fmt.Sprintf("the helper refused it (%s): %s", res.Code, res.Detail))
	default:
		reason := "the helper is not reachable"
		if err != nil {
			reason += ": " + err.Error()
		} else {
			reason = fmt.Sprintf("the helper did not take it (%s): %s", protocol.Truncate(res.Code, 40), res.Detail)
		}
		if a.appl.retryRevision != rev {
			a.appl.retryDelay = 0
		}
		a.appl.retryDelay = min(max(2*a.appl.retryDelay, applyRetryMin), applyRetryMax)
		a.appl.retryRevision, a.appl.retryAt = rev, a.now().Add(a.appl.retryDelay)
		a.log.Warn("desired-state document not handed over; it is offered again later", "revision", rev,
			"retry_in_s", int(a.appl.retryDelay/time.Second), "reason", protocol.Truncate(a.o.Redactor.String(reason), 300))
	}
}

func (a *Agent) refuseDocument(rev int64, reason string) {
	a.appl.refused = rev
	a.log.Error("desired-state document refused; this revision is not offered to the helper again", "revision", rev,
		"reason", protocol.Truncate(a.o.Redactor.String(reason), 300))
}

// applianceTick runs on every loop iteration: it keeps the helper state
// fresh when no heartbeat asked for it (API outage, not paired), runs the
// schedules that are due and the periodic update check.
func (a *Agent) applianceTick(ctx context.Context) {
	if a.o.Appliance == nil || ctx.Err() != nil {
		return
	}
	now := a.now()
	if a.appl.statusAt.IsZero() || now.Sub(a.appl.statusAt) >= max(a.interval, time.Minute) {
		a.refreshApplianceStatus(ctx)
	}
	a.runDueSchedules(ctx, now)
	a.autoUpdateCheck(now)
}
