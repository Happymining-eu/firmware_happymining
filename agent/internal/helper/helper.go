// Package helper implements hm-helper, the narrowly scoped privileged helper.
//
// It knows exactly two actions and nothing else:
//
//	restart-vast-daemon     systemctl restart vastai.service
//	reboot --delay-s N      shutdown -r +M   (60 <= N <= 3600, M = N rounded up to minutes)
//
// Each action is refused unless its switch is enabled in the root-owned file
// /etc/happymining/helper.conf (default: everything disabled). Commands are
// executed with absolute paths and argv arrays; there is no shell and no
// string interpolation. Every invocation is written to the audit log.
package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/config"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/execx"
)

// Actions.
const (
	ActionRestartVastDaemon = "restart-vast-daemon"
	ActionReboot            = "reboot"
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
	CodeInvalid      = "invalid"
	CodeDisabled     = "disabled"
	CodeFailed       = "failed"
	CodeUnauthorized = "unauthorized"
)

// MaxRequestBytes bounds a request read from the socket.
const MaxRequestBytes = 256

// Request is one helper request. It is also the wire format on the socket.
type Request struct {
	Action string `json:"action"`
	DelayS *int64 `json:"delay_s,omitempty"`
}

// Response is the helper's answer.
type Response struct {
	OK     bool   `json:"ok"`
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail"`
}

// Deps are the helper's injectable dependencies.
type Deps struct {
	ConfPath string
	// ConfOwnerUID is the uid that must own the switch file (0 in production).
	ConfOwnerUID uint32
	Runner       execx.Runner
	// Audit receives one line per event.
	Audit func(line string)
}

func (d Deps) audit(format string, args ...any) {
	if d.Audit != nil {
		d.Audit(fmt.Sprintf(format, args...))
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

// Validate checks a request against the fixed argument rules.
func (r Request) Validate() error {
	switch r.Action {
	case ActionRestartVastDaemon:
		if r.DelayS != nil {
			return errors.New("restart-vast-daemon takes no argument")
		}
	case ActionReboot:
		if r.DelayS == nil {
			return errors.New("reboot requires delay_s")
		}
		if *r.DelayS < MinDelayS || *r.DelayS > MaxDelayS {
			return fmt.Errorf("delay_s must be between %d and %d", MinDelayS, MaxDelayS)
		}
	default:
		return errors.New("unknown action")
	}
	return nil
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
	return Response{Code: CodeInvalid, Detail: "unknown action"}
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
// unknown fields, no trailing data, bounded size.
func DecodeRequest(r io.Reader) (Request, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxRequestBytes+1))
	if err != nil {
		return Request{}, errors.New("cannot read request")
	}
	if len(data) > MaxRequestBytes {
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
	return req, req.Validate()
}
