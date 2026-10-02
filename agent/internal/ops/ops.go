// Package ops handles typed operations requested by the HappyMining API.
//
// There is no remote shell. The server can only name an operation type from a
// fixed table; this package independently enforces the agent's own allowlist:
// unknown types, unknown or invalid parameters, expired operations, replayed
// ids and locally disabled types are all rejected. An operation id is durably
// journaled before anything is executed and is never executed twice.
package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/client"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/redact"
)

// MaxPerResponse bounds how many operations of one heartbeat response are
// looked at. The rest stays pending on the server.
const MaxPerResponse = 32

// NotImplemented is the rejection reason for typed operations this agent
// version does not implement.
const NotImplemented = "not implemented in this agent version"

// DiagnosticSections are the sections collect_diagnostics may name.
var DiagnosticSections = []string{"services", "gpu", "disk", "network", "agent"}

// DefaultEnabled are the operation types enabled without local opt-in.
//
// The two appliance operations (docs/appliance.md, section 6.5) are enabled
// here because they are not disruptive for renters: appliance_run_job starts
// one of HappyMining's own jobs (index sync, backup, restart of a catalog
// plugin, update check) and install_update installs HappyMining's own signed
// package. Neither can stop Vast's daemon, a renter container or the machine.
// The real gate for both is on the machine and is off by default: the root
// helper performs them only when its switches in the root-owned helper.conf
// allow it (ALLOW_PLUGINS, ALLOW_BACKUP, ALLOW_UPDATE), and it validates every
// value again. Listing them here only lets the request reach that gate.
var DefaultEnabled = []string{
	protocol.OpRefreshInventory,
	protocol.OpCollectDiagnostics,
	protocol.OpRunPreflight,
	protocol.OpRotateCredential,
	protocol.OpApplianceRunJob,
	protocol.OpInstallUpdate,
}

// ApplianceJobs are the jobs appliance_run_job may name (section 6.5).
var ApplianceJobs = []string{"vectorize_sync", "backup_run", "update_check", "plugin_restart"}

// JobPluginRestart is the only job that takes a plugin.
const JobPluginRestart = "plugin_restart"

// Reboot delay bounds in seconds.
const (
	MinRebootDelayS = 60
	MaxRebootDelayS = 3600
)

// Executor performs the allowlisted actions. Every method is one fixed
// action; there is no generic "run this" entry point.
type Executor interface {
	RefreshInventory(ctx context.Context) (detail string, err error)
	CollectDiagnostics(ctx context.Context, sections []string) (result any, err error)
	RunPreflight(ctx context.Context) (detail string, result any, err error)
	RotateCredential(ctx context.Context) (detail string, err error)
	RestartVastDaemon(ctx context.Context) (detail string, err error)
	Reboot(ctx context.Context, delayS int) (detail string, err error)
	// ApplianceRunJob starts one appliance job; it returns once the job is
	// started (or refused), not when it is finished. plugin is set for
	// plugin_restart only.
	ApplianceRunJob(ctx context.Context, job, plugin string) (detail string, err error)
	// InstallUpdate starts downloading, checking and installing the release
	// version and returns at once. A non-nil error means nothing was started.
	// Otherwise done is called exactly once with the outcome, and it must be
	// called from the goroutine that calls Handle (the agent loop): the
	// journal and the acknowledgement are not safe for concurrent use.
	InstallUpdate(ctx context.Context, version string, done func(detail string, err error)) error
}

// Acker delivers an acknowledgement to the API.
type Acker interface {
	Ack(ctx context.Context, id string, ack *protocol.AckRequest) error
}

// Handler validates, journals, executes and acknowledges operations.
type Handler struct {
	Journal  *Journal
	Exec     Executor
	Acker    Acker
	Redactor *redact.Redactor
	Log      *slog.Logger
	Now      func() time.Time
	enabled  map[string]bool
	// inflight holds the ids of operations that run in the background and
	// have no final outcome yet (install_update).
	inflight map[string]bool
}

// NewHandler builds a Handler. optIn lists the opt-in types the local
// administrator enabled (HM_OPS_ENABLED).
func NewHandler(j *Journal, exec Executor, acker Acker, r *redact.Redactor, log *slog.Logger, now func() time.Time, optIn []string) *Handler {
	if now == nil {
		now = time.Now
	}
	h := &Handler{Journal: j, Exec: exec, Acker: acker, Redactor: r, Log: log, Now: now, enabled: map[string]bool{}, inflight: map[string]bool{}}
	for _, t := range DefaultEnabled {
		h.enabled[t] = true
	}
	for _, t := range optIn {
		h.enabled[t] = true
	}
	return h
}

// Enabled reports whether a type passes the local allowlist.
func (h *Handler) Enabled(opType string) bool { return h.enabled[opType] }

// EnabledTypes lists the locally enabled types (for diagnostics).
func (h *Handler) EnabledTypes() []string {
	var out []string
	for _, t := range knownTypes {
		if h.enabled[t] {
			out = append(out, t)
		}
	}
	return out
}

var knownTypes = []string{
	protocol.OpRefreshInventory, protocol.OpCollectDiagnostics, protocol.OpRunPreflight,
	protocol.OpRotateCredential, protocol.OpRestartVastDaemon, protocol.OpReboot,
	protocol.OpRunBenchmark, protocol.OpApplyHardwareProfile,
	protocol.OpApplianceRunJob, protocol.OpInstallUpdate,
}

func isKnown(t string) bool {
	for _, k := range knownTypes {
		if k == t {
			return true
		}
	}
	return false
}

var reNonce = regexp.MustCompile(`^[A-Za-z0-9_-]{22,256}$`)

// strictDecode decodes params into v and rejects unknown fields and trailing
// data. Absent or null params are an empty object.
func strictDecode(raw json.RawMessage, v any) error {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		raw = json.RawMessage(`{}`)
	}
	if t := bytes.TrimSpace(raw); len(t) == 0 || t[0] != '{' {
		return errors.New("params must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("params contain an unknown field or a value of the wrong type")
	}
	if dec.More() {
		return errors.New("params contain trailing data")
	}
	return nil
}

type noParams struct{}

type diagnosticsParams struct {
	Sections *[]string `json:"sections"`
}

type rebootParams struct {
	DelayS *int64 `json:"delay_s"`
}

// ParseDiagnosticsParams validates collect_diagnostics params.
func ParseDiagnosticsParams(raw json.RawMessage) ([]string, error) {
	var p diagnosticsParams
	if err := strictDecode(raw, &p); err != nil {
		return nil, err
	}
	if p.Sections == nil || len(*p.Sections) == 0 {
		return nil, errors.New("sections must list at least one section")
	}
	if len(*p.Sections) > len(DiagnosticSections) {
		return nil, errors.New("too many sections")
	}
	seen := map[string]bool{}
	for _, s := range *p.Sections {
		ok := false
		for _, allowed := range DiagnosticSections {
			if s == allowed {
				ok = true
			}
		}
		if !ok {
			return nil, errors.New("unknown diagnostics section")
		}
		if seen[s] {
			return nil, errors.New("duplicate diagnostics section")
		}
		seen[s] = true
	}
	return *p.Sections, nil
}

// ParseRebootParams validates reboot params.
func ParseRebootParams(raw json.RawMessage) (int, error) {
	var p rebootParams
	if err := strictDecode(raw, &p); err != nil {
		return 0, err
	}
	if p.DelayS == nil {
		return 0, errors.New("delay_s is required")
	}
	n := *p.DelayS
	if n < MinRebootDelayS || n > MaxRebootDelayS {
		return 0, fmt.Errorf("delay_s must be between %d and %d", MinRebootDelayS, MaxRebootDelayS)
	}
	return int(n), nil
}

var (
	rePluginID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	reVersion  = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
)

// paramKeys decodes params as one JSON object and returns its members. Absent
// or null params are an empty object. A key that is present counts, even with
// a null value, as the server counts it.
func paramKeys(raw json.RawMessage) (map[string]json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return map[string]json.RawMessage{}, nil
	}
	if t := bytes.TrimSpace(raw); t[0] != '{' {
		return nil, errors.New("params must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var m map[string]json.RawMessage
	if err := dec.Decode(&m); err != nil {
		return nil, errors.New("params are not a JSON object")
	}
	if dec.More() {
		return nil, errors.New("params contain trailing data")
	}
	return m, nil
}

// jsonString decodes a JSON string (and nothing else: null is refused).
func jsonString(raw json.RawMessage) (string, bool) {
	if t := bytes.TrimSpace(raw); len(t) == 0 || t[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// ParseApplianceJobParams validates appliance_run_job params exactly as the
// server does: {"job": <one of ApplianceJobs>}, plus "plugin" (a plugin id)
// for plugin_restart and for nothing else.
func ParseApplianceJobParams(raw json.RawMessage) (job, plugin string, err error) {
	m, err := paramKeys(raw)
	if err != nil {
		return "", "", err
	}
	job, ok := jsonString(m["job"])
	known := false
	for _, j := range ApplianceJobs {
		if ok && job == j {
			known = true
		}
	}
	if !known {
		return "", "", errors.New("job must be one of " + strings.Join(ApplianceJobs, ", "))
	}
	if job != JobPluginRestart {
		if len(m) != 1 {
			return "", "", errors.New("only plugin_restart takes a parameter besides job")
		}
		return job, "", nil
	}
	plugin, ok = jsonString(m["plugin"])
	if len(m) != 2 || !ok || !rePluginID.MatchString(plugin) {
		return "", "", errors.New(`plugin_restart needs exactly {"job", "plugin": "<plugin id>"}`)
	}
	return job, plugin, nil
}

// ParseInstallUpdateParams validates install_update params exactly as the
// server does: {"version": "MAJOR.MINOR.PATCH"} and nothing else.
func ParseInstallUpdateParams(raw json.RawMessage) (string, error) {
	m, err := paramKeys(raw)
	if err != nil {
		return "", err
	}
	version, ok := jsonString(m["version"])
	if len(m) != 1 || !ok || !reVersion.MatchString(version) {
		return "", errors.New(`params must be {"version": "<MAJOR.MINOR.PATCH>"}`)
	}
	return version, nil
}

// HandleAll processes the operations of one heartbeat response in order.
func (h *Handler) HandleAll(ctx context.Context, operations []protocol.Operation) {
	if len(operations) > MaxPerResponse {
		h.Log.Warn("too many operations in one response; the rest stays pending",
			"received", len(operations), "handled", MaxPerResponse)
		operations = operations[:MaxPerResponse]
	}
	for _, op := range operations {
		if ctx.Err() != nil {
			return
		}
		h.Handle(ctx, op)
	}
}

// Handle processes one operation and returns the final status it decided
// ("" if the operation could not even be acknowledged).
func (h *Handler) Handle(ctx context.Context, op protocol.Operation) string {
	if !client.ValidOperationID(op.ID) {
		h.Log.Warn("ignoring operation with an invalid id")
		return ""
	}
	log := h.Log.With("operation_id", op.ID, "operation_type", protocol.Truncate(op.Type, 64))
	nonce := op.Nonce
	if !reNonce.MatchString(nonce) {
		// Without a usable nonce the operation cannot be acknowledged as the
		// protocol requires; refuse it and echo nothing questionable.
		nonce = ""
	}

	// Replay protection: an id that is already in the journal is never
	// executed again. The recorded outcome is acknowledged again so that an
	// acknowledgement lost in transit does not turn into a wrong final state.
	if rec, seen := h.Journal.Lookup(op.ID); seen {
		if rec.Final == "" && h.inflight[op.ID] {
			// Still running in the background: the server did not get the
			// first acknowledgement. Say so again; nothing is started twice.
			log.Info("operation repeated while it runs; acknowledged as accepted again")
			h.ack(ctx, log, op.ID, nonce, protocol.AckAccepted, "in progress", nil)
			return protocol.AckAccepted
		}
		log.Warn("replayed operation id; not executing", "recorded_status", rec.Final)
		if rec.Final != "" {
			h.ack(ctx, log, op.ID, nonce, rec.Final,
				"replayed operation id: not executed again; recorded outcome: "+rec.Detail, nil)
			return rec.Final
		}
		h.ack(ctx, log, op.ID, nonce, protocol.AckRejected,
			"replayed operation id: execution started earlier and no outcome was recorded; not executed again", nil)
		return protocol.AckRejected
	}

	expiresAt, _ := time.Parse(time.RFC3339, op.ExpiresAt)
	reject := func(reason string) string {
		// Journal the rejection too, so the id can never be executed later.
		if err := h.Journal.Start(op.ID, op.Type, expiresAt); err == nil {
			if err := h.Journal.Finish(op.ID, protocol.AckRejected, reason); err != nil {
				log.Error("cannot record rejection in the journal", "error", err.Error())
			}
		} else {
			log.Error("cannot record rejection in the journal", "error", err.Error())
		}
		log.Warn("operation rejected", "reason", reason)
		h.ack(ctx, log, op.ID, nonce, protocol.AckRejected, reason, nil)
		return protocol.AckRejected
	}

	if nonce == "" {
		return reject("invalid nonce")
	}
	if !isKnown(op.Type) {
		return reject("unknown operation type")
	}
	if op.Type == protocol.OpRunBenchmark || op.Type == protocol.OpApplyHardwareProfile {
		return reject(NotImplemented)
	}

	var (
		sections    []string
		delayS      int
		job, plugin string
		release     string
		perr        error
	)
	switch op.Type {
	case protocol.OpCollectDiagnostics:
		sections, perr = ParseDiagnosticsParams(op.Params)
	case protocol.OpReboot:
		delayS, perr = ParseRebootParams(op.Params)
	case protocol.OpApplianceRunJob:
		job, plugin, perr = ParseApplianceJobParams(op.Params)
	case protocol.OpInstallUpdate:
		release, perr = ParseInstallUpdateParams(op.Params)
	default:
		perr = strictDecode(op.Params, &noParams{})
	}
	if perr != nil {
		return reject("invalid params: " + perr.Error())
	}

	if _, err := time.Parse(time.RFC3339, op.IssuedAt); err != nil {
		return reject("invalid issued_at")
	}
	if expiresAt.IsZero() {
		return reject("invalid expires_at")
	}
	if !h.Now().Before(expiresAt) {
		return reject("operation expired")
	}
	if !h.enabled[op.Type] {
		return reject("operation type is disabled by local configuration")
	}

	// Record the id before executing. If that fails, nothing is executed.
	if err := h.Journal.Start(op.ID, op.Type, expiresAt); err != nil {
		log.Error("cannot journal operation; not executing", "error", err.Error())
		h.ack(ctx, log, op.ID, nonce, protocol.AckRejected,
			"the operation could not be recorded in the local journal; not executed", nil)
		return protocol.AckRejected
	}

	if op.Type == protocol.OpRestartVastDaemon || op.Type == protocol.OpReboot {
		h.ack(ctx, log, op.ID, nonce, protocol.AckAccepted, "starting", nil)
	}

	if op.Type == protocol.OpInstallUpdate {
		// Downloading a package takes minutes: it runs in the background so
		// that telemetry keeps flowing, and the final acknowledgement follows
		// when it is done. The id is journaled already, so a restart in
		// between never runs it twice.
		h.ack(ctx, log, op.ID, nonce, protocol.AckAccepted, "update to "+release+" starting", nil)
		final := ""
		h.inflight[op.ID] = true
		err := h.Exec.InstallUpdate(ctx, release, func(detail string, err error) {
			if final != "" {
				return // exactly one final outcome
			}
			delete(h.inflight, op.ID)
			// The context of the heartbeat that brought the operation may be
			// gone by now.
			final = h.finish(context.Background(), log, op.ID, nonce, detail, nil, err)
		})
		if err != nil && final == "" {
			delete(h.inflight, op.ID)
			final = h.finish(ctx, log, op.ID, nonce, "", nil, err)
		}
		if final != "" {
			return final
		}
		return protocol.AckAccepted
	}

	var (
		detail string
		result any
		err    error
	)
	switch op.Type {
	case protocol.OpRefreshInventory:
		detail, err = h.Exec.RefreshInventory(ctx)
	case protocol.OpCollectDiagnostics:
		result, err = h.Exec.CollectDiagnostics(ctx, sections)
		detail = "diagnostics collected"
	case protocol.OpRunPreflight:
		detail, result, err = h.Exec.RunPreflight(ctx)
	case protocol.OpRotateCredential:
		detail, err = h.Exec.RotateCredential(ctx)
	case protocol.OpRestartVastDaemon:
		detail, err = h.Exec.RestartVastDaemon(ctx)
	case protocol.OpReboot:
		detail, err = h.Exec.Reboot(ctx, delayS)
	case protocol.OpApplianceRunJob:
		detail, err = h.Exec.ApplianceRunJob(ctx, job, plugin)
	}
	return h.finish(ctx, log, op.ID, nonce, detail, result, err)
}

// finish records the final outcome of an executed operation in the journal and
// acknowledges it. It returns the final status.
func (h *Handler) finish(ctx context.Context, log *slog.Logger, id, nonce, detail string, result any, err error) string {
	status := protocol.AckSucceeded
	if err != nil {
		status = protocol.AckFailed
		detail = err.Error()
		result = nil
	}
	detail = protocol.Truncate(h.Redactor.String(detail), protocol.MaxDetailLen)
	if jerr := h.Journal.Finish(id, status, detail); jerr != nil {
		log.Error("cannot record operation outcome in the journal", "error", jerr.Error())
	}
	log.Info("operation finished", "status", status)
	h.ack(ctx, log, id, nonce, status, detail, result)
	return status
}

// ack redacts and bounds an acknowledgement and sends it.
func (h *Handler) ack(ctx context.Context, log *slog.Logger, id, nonce, status, detail string, result any) {
	raw := json.RawMessage(`{}`)
	if result != nil {
		red, err := h.Redactor.JSON(result)
		switch {
		case err != nil:
			raw = json.RawMessage(`{"error":"result could not be encoded"}`)
		case len(red) > protocol.MaxResultBytes:
			raw = json.RawMessage(`{"truncated":true,"reason":"result larger than 64 KiB"}`)
		default:
			raw = red
		}
	}
	ack := &protocol.AckRequest{
		Status:      status,
		Nonce:       nonce,
		Detail:      protocol.Truncate(h.Redactor.String(detail), protocol.MaxDetailLen),
		Result:      raw,
		CompletedAt: protocol.FormatTime(h.Now()),
	}
	if err := h.Acker.Ack(ctx, id, ack); err != nil {
		if client.IsFinalForAck(err) {
			log.Info("acknowledgement is final on the server", "status", status, "error", err.Error())
			return
		}
		log.Warn("acknowledgement not delivered; the recorded outcome is sent again if the server repeats the operation",
			"status", status, "error", err.Error())
	}
}
