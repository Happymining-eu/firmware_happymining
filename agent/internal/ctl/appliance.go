package ctl

// happyminingctl appliance ... and backup ... (docs/appliance.md, sections 6.4,
// 10 and 11, and the helper interface, "Root command-line actions").
//
// `appliance status` reads the appliance state from the root helper through
// its socket, as the agent does, and prints it. Everything else is a local
// root action of the helper itself: when run as root, happyminingctl executes
// /usr/lib/happymining/hm-helper with a fixed argument list, the terminal
// passed through (the helper asks for secrets and confirmations itself, with
// echo off where it matters); otherwise it explains that sudo is needed. No
// secret passes through happyminingctl's own memory or arguments.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/agent"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/helper"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/redact"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/seal"
)

// HelperPath is the root helper's fixed location.
const HelperPath = "/usr/lib/happymining/hm-helper"

const applianceUsage = `usage:
  happyminingctl appliance status [--json]   appliance state reported by the root helper
  sudo happyminingctl appliance secret set <name>
                                            store a secret for the local profile (read from standard input)
  sudo happyminingctl appliance purge <plugin id>
                                            delete a removed plugin's data on this machine
  sudo happyminingctl appliance token [vectorizer]
                                            create (if missing) and print the vectorizer token
`

const backupUsage = `usage:
  sudo happyminingctl backup init            create the backup key and print the recovery key once
  sudo happyminingctl backup restore --from <archive> [--to <directory>]
                                            restore an archive (asks for the recovery key)
`

// defaultExecHelper runs the helper with the terminal attached and a minimal
// environment, and returns its exit status.
func defaultExecHelper(path string, args []string) (int, error) {
	cmd := exec.Command(path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

// defaultHelperStatus asks the helper socket for the appliance state.
func defaultHelperStatus(ctx context.Context, socket string) (helper.Response, error) {
	c := &helper.Client{SocketPath: socket, Timeout: 20 * time.Second}
	return c.Do(ctx, helper.Request{Action: agent.ActionApplianceStatus})
}

func (a *app) euid() int {
	if a.env.Geteuid != nil {
		return a.env.Geteuid()
	}
	return os.Geteuid()
}

var rePluginID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

func (a *app) appliance(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.env.Stderr, applianceUsage)
		return ExitUsage
	}
	switch {
	case args[0] == "status":
		return a.applianceStatus(args[1:])
	case args[0] == "secret" && len(args) == 3 && args[1] == "set":
		if !seal.ValidName(args[2]) {
			fmt.Fprintf(a.env.Stderr, "error: %q is not a secret name (for example nas.docs.password)\n", args[2])
			return ExitUsage
		}
		return a.rootHelper("appliance secret set "+args[2], "secret-set", args[2])
	case args[0] == "purge" && len(args) == 2:
		if !rePluginID.MatchString(args[1]) {
			fmt.Fprintf(a.env.Stderr, "error: %q is not a plugin id\n", args[1])
			return ExitUsage
		}
		return a.rootHelper("appliance purge "+args[1], "appliance-purge", args[1])
	case args[0] == "token" && (len(args) == 1 || (len(args) == 2 && args[1] == "vectorizer")):
		return a.rootHelper("appliance token vectorizer", "vectorizer-token")
	case args[0] == "help" || args[0] == "--help" || args[0] == "-h":
		fmt.Fprint(a.env.Stdout, applianceUsage)
		return ExitOK
	}
	fmt.Fprint(a.env.Stderr, applianceUsage)
	return ExitUsage
}

func (a *app) backup(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.env.Stderr, backupUsage)
		return ExitUsage
	}
	switch args[0] {
	case "init":
		if len(args) != 1 {
			fmt.Fprint(a.env.Stderr, backupUsage)
			return ExitUsage
		}
		return a.rootHelper("backup init", "backup-init")
	case "restore":
		fs := flag.NewFlagSet("happyminingctl backup restore", flag.ContinueOnError)
		fs.SetOutput(a.env.Stderr)
		from := fs.String("from", "", "archive to restore (hm-backup-*.hmbk)")
		to := fs.String("to", "", "directory to restore into (default: a new directory chosen by the helper; never over live data)")
		if c, ok := a.parse(fs, args[1:]); !ok {
			return c
		}
		if *from == "" {
			fmt.Fprintln(a.env.Stderr, "error: --from <archive> is required")
			return ExitUsage
		}
		argv := []string{"backup-restore"}
		for _, p := range []struct{ flag, value string }{{"--from", *from}, {"--to", *to}} {
			if p.value == "" {
				continue
			}
			abs, err := absolute(p.value)
			if err != nil {
				fmt.Fprintf(a.env.Stderr, "error: %s: %v\n", p.flag, err)
				return ExitUsage
			}
			argv = append(argv, p.flag, abs)
		}
		return a.rootHelper("backup restore", argv...)
	case "help", "--help", "-h":
		fmt.Fprint(a.env.Stdout, backupUsage)
		return ExitOK
	}
	fmt.Fprint(a.env.Stderr, backupUsage)
	return ExitUsage
}

// absolute makes a path given on the command line absolute, so that the
// helper never interprets it as an option and its audit line is unambiguous.
func absolute(p string) (string, error) {
	if strings.ContainsRune(p, 0) || strings.ContainsAny(p, "\n\r") {
		return "", errors.New("invalid path")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

// rootHelper runs the helper's root action argv, or explains sudo.
func (a *app) rootHelper(what string, argv ...string) int {
	if a.euid() != 0 {
		fmt.Fprintf(a.env.Stderr, "error: this is a root action of the privileged helper; run: sudo happyminingctl %s\n", what)
		return ExitFail
	}
	run := a.env.ExecHelper
	if run == nil {
		run = defaultExecHelper
	}
	code, err := run(HelperPath, argv)
	if err != nil {
		return a.fail("cannot run %s: %v", HelperPath, err)
	}
	if code != 0 {
		fmt.Fprintf(a.env.Stderr, "hm-helper %s exited with status %d\n", argv[0], code)
		return ExitFail
	}
	return ExitOK
}

// applianceStatusReport is the output of `appliance status --json`.
type applianceStatusReport struct {
	appliance.Reported
	AppliedSchedules []appliance.Schedule `json:"applied_schedules"`
}

func (a *app) applianceStatus(args []string) int {
	fs := a.flagSet("appliance status")
	asJSON := fs.Bool("json", false, "print JSON")
	if c, ok := a.parse(fs, args); !ok {
		return c
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("%v", err)
	}
	ask := a.env.HelperStatus
	if ask == nil {
		ask = defaultHelperStatus
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	resp, err := ask(ctx, cfg.HelperSocket)
	switch {
	case err != nil && errors.Is(err, os.ErrPermission), err != nil && strings.Contains(err.Error(), "permission denied"):
		return a.fail("the helper socket %s is reserved to root and the agent account; run: sudo happyminingctl appliance status", cfg.HelperSocket)
	case err != nil:
		return a.fail("the privileged helper is not reachable at %s: %v (is happymining-helper.socket running?)", cfg.HelperSocket, err)
	case !resp.OK && resp.Code == agent.CodeUnauthorized:
		return a.fail("the privileged helper only answers root and the agent account; run: sudo happyminingctl appliance status")
	case !resp.OK:
		return a.fail("the privileged helper refused (%s): %s", resp.Code, resp.Detail)
	}
	var raw struct {
		appliance.Reported
		AppliedSchedules []json.RawMessage `json:"applied_schedules"`
	}
	if err := json.Unmarshal(resp.Result, &raw); err != nil {
		return a.fail("the privileged helper sent an appliance status this command does not understand")
	}
	rep := applianceStatusReport{Reported: raw.Reported}
	for _, item := range raw.AppliedSchedules {
		var s appliance.Schedule
		if json.Unmarshal(item, &s) == nil && rePluginID.MatchString(s.ID) && s.Spec().Validate() == nil {
			rep.AppliedSchedules = append(rep.AppliedSchedules, s)
		}
	}
	// The agent's own schedule history (last run and outcome), when readable.
	rep.Schedules = scheduleHistory(cfg.StateDir)
	redactor := redact.New()
	scrub(&rep.Reported, redactor)
	rep.Sanitize()
	if rep.AppliedSchedules == nil {
		rep.AppliedSchedules = []appliance.Schedule{}
	}
	if *asJSON {
		enc := json.NewEncoder(a.env.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return ExitOK
	}
	printApplianceStatus(a.env.Stdout, &rep)
	return ExitOK
}

// scheduleHistory reads the agent's schedules.json (last run and outcome).
func scheduleHistory(stateDir string) []appliance.ScheduleState {
	data, err := os.ReadFile(filepath.Join(stateDir, agent.SchedulesFileName))
	if err != nil || len(data) > 64*1024 {
		return nil
	}
	var f struct {
		Schedules map[string]struct {
			LastRunAt  string `json:"last_run_at"`
			LastStatus string `json:"last_status"`
		} `json:"schedules"`
	}
	if json.Unmarshal(data, &f) != nil {
		return nil
	}
	var out []appliance.ScheduleState
	for id, h := range f.Schedules {
		out = append(out, appliance.ScheduleState{ID: id, LastRunAt: h.LastRunAt, LastStatus: h.LastStatus})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func scrub(rep *appliance.Reported, r *redact.Redactor) {
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

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func printApplianceStatus(w io.Writer, rep *applianceStatusReport) {
	fmt.Fprintln(w, "Appliance (as reported by the privileged helper)")
	fmt.Fprintf(w, "  Control:      %s\n", rep.Control)
	fmt.Fprintf(w, "  Mode:         %s\n", rep.Mode)
	fmt.Fprintf(w, "  Applied:      revision %d, %s\n", rep.AppliedRevision, rep.ApplyStatus)
	if rep.ApplyDetail != "" {
		fmt.Fprintf(w, "  Detail:       %s\n", rep.ApplyDetail)
	}
	c := rep.Capabilities
	fmt.Fprintf(w, "  Allowed:      plugins %s, nas %s, backup %s, update %s; docker installed: %s\n",
		yesNo(c.Plugins), yesNo(c.NAS), yesNo(c.Backup), yesNo(c.Update), yesNo(c.Docker))
	fmt.Fprintf(w, "  Sealing key:  %s\n", orDash(rep.SealPublicKey))
	var catalog []string
	for _, e := range rep.Catalog {
		catalog = append(catalog, e.ID+" "+e.Version)
	}
	fmt.Fprintf(w, "  Catalog:      %s\n", orDash(strings.Join(catalog, ", ")))
	fmt.Fprintln(w, "Plugins:")
	if len(rep.Plugins) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	for _, p := range rep.Plugins {
		var ports []string
		for _, port := range p.Ports {
			ports = append(ports, fmt.Sprint(port))
		}
		fmt.Fprintf(w, "  %-14s %-15s version %-6s ports %-12s %s\n", p.ID, p.State, orDash(p.Version), orDash(strings.Join(ports, ",")), p.Detail)
	}
	fmt.Fprintln(w, "NAS:")
	if len(rep.NAS) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	for _, n := range rep.NAS {
		fmt.Fprintf(w, "  %-14s %-10s %s\n", n.ID, n.State, n.Detail)
	}
	fmt.Fprintln(w, "Secrets (names and state only):")
	if len(rep.Secrets) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	for _, s := range rep.Secrets {
		fmt.Fprintf(w, "  %-32s %s\n", s.Name, s.State)
	}
	v := rep.Vectorizer
	fmt.Fprintf(w, "Vectorizer:     %s; last run %s, last ok %s; %d indexed, %d failed, %d skipped, %d passages %s\n",
		v.State, orDash(v.LastRunAt), orDash(v.LastOKAt), v.FilesIndexed, v.FilesFailed, v.FilesSkipped, v.Chunks, v.Detail)
	b := rep.Backup
	fmt.Fprintf(w, "Backup:         %s; key present %s (key id %s); last ok %s, %d bytes %s\n",
		b.State, yesNo(b.KeyPresent), orDash(b.KeyID), orDash(b.LastOKAt), b.LastSizeBytes, b.Detail)
	u := rep.Update
	fmt.Fprintf(w, "Update:         running %s; %s; target %s %s\n", orDash(u.CurrentVersion), u.State, orDash(u.TargetVersion), u.Detail)
	fmt.Fprintln(w, "Schedules (applied document; last run from the agent's history):")
	if len(rep.AppliedSchedules) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	history := map[string]appliance.ScheduleState{}
	for _, h := range rep.Schedules {
		history[h.ID] = h
	}
	for _, s := range rep.AppliedSchedules {
		when := fmt.Sprintf("minute %02d", s.Minute)
		if s.Hour != nil {
			when = fmt.Sprintf("%02d:%02d", *s.Hour, s.Minute)
		}
		if s.Weekday != nil {
			when = []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}[*s.Weekday] + " " + when
		}
		job := s.Job
		if s.Plugin != "" {
			job += " " + s.Plugin
		}
		h := history[s.ID]
		enabled := "enabled"
		if !s.Enabled {
			enabled = "disabled"
		}
		fmt.Fprintf(w, "  %-16s %-26s %-7s %-14s %-8s last %s %s\n", s.ID, job, s.Every, when, enabled,
			orDash(h.LastRunAt), orDash(h.LastStatus))
	}
}
