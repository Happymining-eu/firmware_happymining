// Package helper implements hm-helper, the narrowly scoped privileged helper.
//
// Over its root-owned socket it knows these actions and nothing else:
//
//	restart-vast-daemon     systemctl restart vastai.service
//	reboot --delay-s N      shutdown -r +M   (60 <= N <= 3600, M = N rounded up to minutes)
//	appliance-status        the appliance state (files only; see applier.Status)
//	appliance-apply         validate, store and hand the desired-state document to
//	                        happymining-appliance-apply.service
//	appliance-run-job       start happymining-appliance-job@<job>.service
//	update-install          verify and stage a signed release, then start
//	                        happymining-update-install.service
//
// The socket actions are quick: none of them runs Docker, mount, a backup or
// dpkg. The heavy work runs in dedicated oneshot units, as root command-line
// actions of hm-helper (cmd/hm-helper), in package applier.
//
// Each action is refused unless its switch is enabled in the root-owned file
// /etc/happymining/helper.conf (default: everything disabled;
// appliance-status needs none). Commands are executed with absolute paths and
// argv arrays; there is no shell and no string interpolation. Every
// invocation is written to the audit log, which never receives a secret.
package helper

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/applier"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/config"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/execx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/release"
)

// Actions.
const (
	ActionRestartVastDaemon = "restart-vast-daemon"
	ActionReboot            = "reboot"
	ActionApplianceStatus   = "appliance-status"
	ActionApplianceApply    = "appliance-apply"
	ActionApplianceRunJob   = "appliance-run-job"
	ActionUpdateInstall     = "update-install"
)

// Jobs appliance-run-job accepts (docs/appliance.md, 6.5; update_check is
// the agent's own job and never reaches the helper).
const (
	JobVectorizeSync = applier.JobVectorizeSync
	JobBackupRun     = applier.JobBackupRun
	JobPluginRestart = applier.JobPluginRestart
)

// Fixed command lines. The Vast unit name is not verified against Vast
// documentation (see README, "Not verified here").
const (
	SystemctlPath = "/usr/bin/systemctl"
	ShutdownPath  = "/usr/sbin/shutdown"
	VastUnit      = "vastai.service"
	RebootMessage = "HappyMining: reboot requested through the fleet management agent"
)

// Reboot delay bounds in seconds.
const (
	MinDelayS = 60
	MaxDelayS = 3600
)

// Response codes.
const (
	CodeInvalid           = "invalid"
	CodeDisabled          = "disabled"
	CodeFailed            = "failed"
	CodeUnauthorized      = "unauthorized"
	CodeLocallyControlled = "locally_controlled"
	CodeBusy              = "busy"
)

// Size limits of the socket protocol. A request line is at most
// MaxRequestBytes for every action but appliance-apply (MaxApplyRequestBytes:
// a document of up to 64 KiB with its envelope) and update-install
// (MaxUpdateRequestBytes: a manifest of up to 16 KiB in base64, see the
// helper interface's "Contract questions"). A response line is at most
// MaxResponseBytes.
const (
	MaxRequestBytes       = 256
	MaxApplyRequestBytes  = 96 * 1024
	MaxUpdateRequestBytes = 32 * 1024
	MaxResponseBytes      = 256 * 1024
)

// Field bounds of update-install.
const (
	maxManifestB64  = (release.MaxManifestBytes + 2) / 3 * 4
	maxSignatureB64 = 128
	maxArtifactPath = 512
)

// Request is one helper request. It is also the wire format on the socket.
type Request struct {
	Action       string          `json:"action"`
	DelayS       *int64          `json:"delay_s,omitempty"`       // reboot only
	Document     json.RawMessage `json:"document,omitempty"`      // appliance-apply only
	Job          string          `json:"job,omitempty"`           // appliance-run-job only
	Plugin       string          `json:"plugin,omitempty"`        // appliance-run-job with job plugin_restart only
	Version      string          `json:"version,omitempty"`       // update-install only
	ManifestB64  string          `json:"manifest_b64,omitempty"`  // update-install only
	SignatureB64 string          `json:"signature_b64,omitempty"` // update-install only
	ArtifactPath string          `json:"artifact_path,omitempty"` // update-install only
}

// Response is the helper's answer.
type Response struct {
	OK     bool   `json:"ok"`
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail"`
	// Result is set for appliance-status (a StatusResult) and
	// appliance-apply (an ApplyResult).
	Result json.RawMessage `json:"result,omitempty"`
}

// StatusResult is the result of appliance-status: the JSON of
// appliance.Reported without "schedules", plus "applied_schedules".
type StatusResult = applier.StatusResult

// ApplyResult is the result of appliance-apply.
type ApplyResult = applier.ApplyResult

// Deps are the helper's injectable dependencies.
type Deps struct {
	ConfPath string
	// ConfOwnerUID is the uid that must own the switch file and every
	// root-only file of the helper (0 in production).
	ConfOwnerUID uint32
	Runner       execx.Runner
	// Audit receives one line per event.
	Audit func(line string)
	// Paths are the appliance locations (applier.DefaultPaths in
	// production). A zero value disables every appliance action, so that
	// nothing can fall back to real system paths.
	Paths applier.Paths
	// AgentUID is the uid of the unprivileged agent (owner of downloads).
	AgentUID uint32
	// Version is the installed agent version.
	Version string
	// Now, Sleep and HasDocker are optional (tests).
	Now       func() time.Time
	Sleep     func(time.Duration)
	HasDocker func() bool
}

func (d Deps) audit(format string, args ...any) {
	if d.Audit != nil {
		d.Audit(fmt.Sprintf(format, args...))
	}
}

// Engine returns the appliance engine for the given switches.
func (d Deps) Engine(conf config.Helper) *applier.Env {
	return &applier.Env{
		Paths: d.Paths, Runner: d.Runner, Switches: conf, OwnerUID: d.ConfOwnerUID, AgentUID: d.AgentUID,
		Version: d.Version, Now: d.Now, Sleep: d.Sleep, Audit: d.Audit, HasDocker: d.HasDocker,
	}
}

var reDelay = regexp.MustCompile(`^[0-9]{1,4}$`)

// ParseArgs validates a command line (without the program name). Only the two
// exact shapes are accepted.
func ParseArgs(args []string) (Request, error) {
	switch {
	case len(args) == 1 && args[0] == ActionRestartVastDaemon:
		return Request{Action: ActionRestartVastDaemon}, nil
	case len(args) == 3 && args[0] == ActionReboot && args[1] == "--delay-s":
		if !reDelay.MatchString(args[2]) {
			return Request{}, errors.New("--delay-s must be a whole number of seconds")
		}
		n, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil {
			return Request{}, errors.New("--delay-s must be a whole number of seconds")
		}
		req := Request{Action: ActionReboot, DelayS: &n}
		return req, req.Validate()
	}
	return Request{}, errors.New("usage: hm-helper restart-vast-daemon | hm-helper reboot --delay-s N")
}

var reVersion = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)

// Validate checks a request against the fixed argument rules: each action
// takes exactly its own fields.
func (r Request) Validate() error {
	has := map[string]bool{
		"delay_s": r.DelayS != nil, "document": len(r.Document) > 0, "job": r.Job != "", "plugin": r.Plugin != "",
		"version": r.Version != "", "manifest_b64": r.ManifestB64 != "", "signature_b64": r.SignatureB64 != "",
		"artifact_path": r.ArtifactPath != "",
	}
	only := func(fields ...string) error {
		allowed := map[string]bool{}
		for _, f := range fields {
			allowed[f] = true
		}
		for f, set := range has {
			if set && !allowed[f] {
				return fmt.Errorf("%s does not take %s", r.Action, f)
			}
		}
		return nil
	}
	switch r.Action {
	case ActionRestartVastDaemon:
		if r.DelayS != nil {
			return errors.New("restart-vast-daemon takes no argument")
		}
		return only()
	case ActionReboot:
		if r.DelayS == nil {
			return errors.New("reboot requires delay_s")
		}
		if *r.DelayS < MinDelayS || *r.DelayS > MaxDelayS {
			return fmt.Errorf("delay_s must be between %d and %d", MinDelayS, MaxDelayS)
		}
		return only("delay_s")
	case ActionApplianceStatus:
		return only()
	case ActionApplianceApply:
		if len(r.Document) == 0 {
			return errors.New("appliance-apply requires document")
		}
		if len(r.Document) > appliance.MaxDocumentBytes {
			return fmt.Errorf("the document is larger than %d bytes", appliance.MaxDocumentBytes)
		}
		return only("document")
	case ActionApplianceRunJob:
		switch r.Job {
		case JobVectorizeSync, JobBackupRun:
			if r.Plugin != "" {
				return fmt.Errorf("job %s takes no plugin", r.Job)
			}
		case JobPluginRestart:
			if !applier.ValidID(r.Plugin) {
				return errors.New("job plugin_restart requires a valid plugin id")
			}
		default:
			return errors.New("job must be vectorize_sync, backup_run or plugin_restart")
		}
		return only("job", "plugin")
	case ActionUpdateInstall:
		if !reVersion.MatchString(r.Version) {
			return errors.New("version must be MAJOR.MINOR.PATCH")
		}
		if r.ManifestB64 == "" || len(r.ManifestB64) > maxManifestB64 {
			return errors.New("manifest_b64 is required and bounded")
		}
		if _, err := base64.StdEncoding.Strict().DecodeString(r.ManifestB64); err != nil {
			return errors.New("manifest_b64 is not base64")
		}
		if r.SignatureB64 == "" || len(r.SignatureB64) > maxSignatureB64 {
			return errors.New("signature_b64 is required and bounded")
		}
		if len(r.ArtifactPath) > maxArtifactPath || !filepath.IsAbs(r.ArtifactPath) ||
			filepath.Clean(r.ArtifactPath) != r.ArtifactPath || strings.ContainsAny(r.ArtifactPath, "\x00\n") {
			return errors.New("artifact_path must be a clean absolute path")
		}
		return only("version", "manifest_b64", "signature_b64", "artifact_path")
	}
	return errors.New("unknown action")
}

// maxRequestFor is the largest request line of an action.
func maxRequestFor(action string) int {
	switch action {
	case ActionApplianceApply:
		return MaxApplyRequestBytes
	case ActionUpdateInstall:
		return MaxUpdateRequestBytes
	}
	return MaxRequestBytes
}

// LoadConf reads the switch file. A missing file means everything is
// disabled. A file that is a symlink, is not a regular file, is not owned by
// ownerUID or is writable by group or others is refused. The checks are made
// on the opened file, so the file that is checked is the file that is read.
func LoadConf(path string, ownerUID uint32) (config.Helper, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return config.Helper{}, nil
		}
		return config.Helper{}, fmt.Errorf("%s cannot be opened (a symlink is not accepted): %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return config.Helper{}, err
	}
	if !fi.Mode().IsRegular() {
		return config.Helper{}, fmt.Errorf("%s is not a regular file", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != ownerUID {
		return config.Helper{}, fmt.Errorf("%s is not owned by uid %d", path, ownerUID)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return config.Helper{}, fmt.Errorf("%s is writable by group or others", path)
	}
	conf, err := config.ParseHelper(f)
	if err != nil {
		return config.Helper{}, fmt.Errorf("%s: %w", path, err)
	}
	return conf, nil
}

// RebootMinutes converts a delay in seconds to the whole minutes shutdown(8)
// understands, rounding up so the machine never reboots earlier than asked.
func RebootMinutes(delayS int64) int64 { return (delayS + 59) / 60 }

// Execute validates and performs one request.
func Execute(ctx context.Context, req Request, d Deps) Response {
	if err := req.Validate(); err != nil {
		d.audit("refused invalid request: %v", err)
		return Response{Code: CodeInvalid, Detail: err.Error()}
	}
	conf, err := LoadConf(d.ConfPath, d.ConfOwnerUID)
	if err != nil {
		d.audit("refused action=%s: switch file unusable: %v", req.Action, err)
		return Response{Code: CodeDisabled, Detail: "helper switch file is unusable; every action is disabled"}
	}
	switch req.Action {
	case ActionRestartVastDaemon:
		if !conf.AllowRestartVastDaemon {
			d.audit("refused action=%s: disabled in %s", req.Action, d.ConfPath)
			return Response{Code: CodeDisabled, Detail: "restart-vast-daemon is disabled in the helper switch file"}
		}
		d.audit("executing action=%s: %s restart %s", req.Action, SystemctlPath, VastUnit)
		return run(ctx, d, req.Action, 120*time.Second, "Vast daemon restart requested",
			SystemctlPath, "restart", VastUnit)
	case ActionReboot:
		if !conf.AllowReboot {
			d.audit("refused action=%s: disabled in %s", req.Action, d.ConfPath)
			return Response{Code: CodeDisabled, Detail: "reboot is disabled in the helper switch file"}
		}
		minutes := RebootMinutes(*req.DelayS)
		d.audit("executing action=%s delay_s=%d: %s -r +%d", req.Action, *req.DelayS, ShutdownPath, minutes)
		return run(ctx, d, req.Action, 30*time.Second,
			fmt.Sprintf("reboot scheduled in %d minute(s) (requested delay %d s, rounded up to whole minutes)", minutes, *req.DelayS),
			ShutdownPath, "-r", "+"+strconv.FormatInt(minutes, 10), RebootMessage)
	}

	// Appliance actions.
	if err := d.Paths.Check(); err != nil {
		d.audit("refused action=%s: the appliance paths are not configured", req.Action)
		return Response{Code: CodeFailed, Detail: "the helper is not configured for appliance actions"}
	}
	engine := d.Engine(conf)
	switch req.Action {
	case ActionApplianceStatus:
		res, err := applier.Status(ctx, engine)
		if err != nil {
			d.audit("action=%s failed: %v", req.Action, err)
			return Response{Code: CodeFailed, Detail: "the appliance state cannot be read: " + clip(err.Error(), 300)}
		}
		return withResult(Response{OK: true, Detail: "appliance state"}, res)
	case ActionApplianceApply:
		if !conf.AllowPlugins && !conf.AllowNAS {
			d.audit("action=%s: applying is disabled in %s; the document is only validated and stored", req.Action, d.ConfPath)
		}
		return fromOutcome(applier.QuickApply(ctx, engine, req.Document))
	case ActionApplianceRunJob:
		d.audit("executing action=%s job=%s plugin=%s", req.Action, req.Job, req.Plugin)
		return fromOutcome(applier.QuickRunJob(ctx, engine, req.Job, req.Plugin))
	case ActionUpdateInstall:
		d.audit("executing action=%s version=%s", req.Action, req.Version)
		return fromOutcome(applier.QuickUpdateInstall(ctx, engine, applier.UpdateRequest{
			Version: req.Version, ManifestB64: req.ManifestB64, SignatureB64: req.SignatureB64, ArtifactPath: req.ArtifactPath,
		}))
	}
	return Response{Code: CodeInvalid, Detail: "unknown action"}
}

func fromOutcome(o applier.Outcome) Response {
	resp := Response{OK: o.OK, Code: o.Code, Detail: o.Detail}
	if o.Result != nil {
		return withResult(resp, o.Result)
	}
	return resp
}

func withResult(resp Response, result any) Response {
	raw, err := json.Marshal(result)
	if err != nil {
		return Response{Code: CodeFailed, Detail: "the result cannot be encoded"}
	}
	resp.Result = raw
	return resp
}

func clip(s string, max int) string {
	if len(s) > max {
		s = s[:max]
	}
	return strings.ToValidUTF8(s, "?")
}

func run(ctx context.Context, d Deps, action string, timeout time.Duration, okDetail, path string, args ...string) Response {
	res, err := d.Runner.Run(ctx, timeout, path, args...)
	if err != nil {
		d.audit("action=%s failed: %v", action, err)
		return Response{Code: CodeFailed, Detail: "command could not be run: " + err.Error()}
	}
	if res.ExitCode != 0 {
		stderr := strings.TrimSpace(string(bytes.ToValidUTF8(res.Stderr, []byte("?"))))
		if len(stderr) > 300 {
			stderr = stderr[:300]
		}
		d.audit("action=%s failed: exit status %d: %s", action, res.ExitCode, stderr)
		return Response{Code: CodeFailed, Detail: fmt.Sprintf("command exited with status %d: %s", res.ExitCode, stderr)}
	}
	d.audit("action=%s succeeded", action)
	return Response{OK: true, Detail: okDetail}
}

// DecodeRequest strictly decodes one request: a single JSON object, no
// unknown fields, no trailing data, bounded size (the bound depends on the
// action, see MaxRequestBytes).
func DecodeRequest(r io.Reader) (Request, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxApplyRequestBytes+2))
	if err != nil {
		return Request{}, errors.New("cannot read request")
	}
	if len(bytes.TrimRight(data, "\n")) > MaxApplyRequestBytes {
		return Request{}, errors.New("request too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		return Request{}, errors.New("request is not a valid helper request")
	}
	if dec.More() {
		return Request{}, errors.New("trailing data after request")
	}
	if len(bytes.TrimRight(data, "\n")) > maxRequestFor(req.Action) {
		return Request{}, errors.New("request too large")
	}
	return req, req.Validate()
}
