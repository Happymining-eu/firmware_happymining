package ctl

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/agent"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/helper"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/seal"
)

type execCall struct {
	path string
	args []string
}

// rootFixture is a fixture whose root actions are recorded instead of run.
func rootFixture(t *testing.T, euid int, exitCode int) (*fixture, *[]execCall) {
	t.Helper()
	f := newFixture(t)
	var calls []execCall
	f.env.Geteuid = func() int { return euid }
	f.env.ExecHelper = func(path string, args []string) (int, error) {
		calls = append(calls, execCall{path, append([]string(nil), args...)})
		return exitCode, nil
	}
	return f, &calls
}

func TestRootActionsExecuteTheHelperWithFixedArguments(t *testing.T) {
	f, calls := rootFixture(t, 0, 0)
	wd, _ := os.Getwd()
	cases := []struct {
		args []string
		want []string
	}{
		{[]string{"appliance", "secret", "set", "nas.docs.password"}, []string{"secret-set", "nas.docs.password"}},
		{[]string{"appliance", "purge", "open-webui"}, []string{"appliance-purge", "open-webui"}},
		{[]string{"appliance", "token"}, []string{"vectorizer-token"}},
		{[]string{"appliance", "token", "vectorizer"}, []string{"vectorizer-token"}},
		{[]string{"backup", "init"}, []string{"backup-init"}},
		{[]string{"backup", "restore", "--from", "/srv/x/hm-backup-a.hmbk"}, []string{"backup-restore", "--from", "/srv/x/hm-backup-a.hmbk"}},
		{[]string{"backup", "restore", "--from", "archive.hmbk", "--to", "restored"},
			[]string{"backup-restore", "--from", filepath.Join(wd, "archive.hmbk"), "--to", filepath.Join(wd, "restored")}},
		{[]string{"backup", "restore", "--from", "-rf"}, []string{"backup-restore", "--from", filepath.Join(wd, "-rf")}},
	}
	for _, tc := range cases {
		before := len(*calls)
		if code := f.run(tc.args...); code != ExitOK {
			t.Fatalf("%v: exit %d: %s", tc.args, code, f.output())
		}
		if len(*calls) != before+1 {
			t.Fatalf("%v: helper not run", tc.args)
		}
		got := (*calls)[before]
		if got.path != HelperPath || strings.Join(got.args, "\x00") != strings.Join(tc.want, "\x00") {
			t.Fatalf("%v: ran %s %q, want %q", tc.args, got.path, got.args, tc.want)
		}
	}
}

func TestRootActionsExplainSudoAndValidateArguments(t *testing.T) {
	f, calls := rootFixture(t, 1000, 0)
	for _, args := range [][]string{
		{"appliance", "secret", "set", "nas.docs.password"}, {"appliance", "purge", "ollama"}, {"appliance", "token"},
		{"backup", "init"}, {"backup", "restore", "--from", "/tmp/a.hmbk"},
	} {
		if code := f.run(args...); code != ExitFail || !strings.Contains(f.stderr.String(), "sudo happyminingctl") {
			t.Fatalf("%v: %d %s", args, code, f.output())
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("the helper ran without root: %v", *calls)
	}

	g, calls := rootFixture(t, 0, 0)
	for _, args := range [][]string{
		{"appliance"}, {"appliance", "frob"}, {"appliance", "secret", "set"},
		{"appliance", "secret", "set", "Not A Name"}, {"appliance", "secret", "set", "a", "b"},
		{"appliance", "secret", "get", "nas.docs.password"}, {"appliance", "purge"},
		{"appliance", "purge", "../etc"}, {"appliance", "purge", "Ollama"}, {"appliance", "token", "other"},
		{"backup"}, {"backup", "init", "now"}, {"backup", "restore"}, {"backup", "restore", "--to", "/x"},
		{"backup", "restore", "--from", "a\nb"}, {"backup", "restore", "--from", "a", "extra"},
		{"backup", "delete"},
	} {
		if code := g.run(args...); code != ExitUsage {
			t.Errorf("%v: exit %d, want usage error: %s", args, code, g.output())
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("the helper ran for invalid input: %v", *calls)
	}
}

func TestRootActionFailureIsReported(t *testing.T) {
	f, _ := rootFixture(t, 0, 1)
	if code := f.run("backup", "init"); code != ExitFail || !strings.Contains(f.stderr.String(), "exited with status 1") {
		t.Fatalf("%d %s", code, f.output())
	}
	f.env.ExecHelper = func(string, []string) (int, error) { return -1, errors.New("no such file") }
	if code := f.run("backup", "init"); code != ExitFail || !strings.Contains(f.stderr.String(), HelperPath) {
		t.Fatalf("%d %s", code, f.output())
	}
}

func statusResult(t *testing.T, mod func(m map[string]any)) helper.Response {
	t.Helper()
	k, _ := seal.Generate()
	m := map[string]any{
		"schema": 1, "control": "cloud", "applied_revision": 12, "apply_status": "partial",
		"apply_detail": "nas docs: mount failed", "mode": "private_ai", "seal_public_key": k.Public(),
		"capabilities": map[string]bool{"plugins": true, "nas": true, "backup": false, "update": true, "docker": true},
		"catalog":      []map[string]string{{"id": "ollama", "version": "1"}},
		"plugins":      []map[string]any{{"id": "ollama", "state": "running", "detail": "", "version": "1", "ports": []int{11434}}},
		"nas":          []map[string]any{{"id": "docs", "state": "error", "detail": "mount error(13): Permission denied"}},
		"secrets":      []map[string]any{{"name": "nas.docs.password", "state": "ok"}},
		"vectorizer":   map[string]any{"state": "idle", "last_run_at": "2026-10-02T02:30:00Z", "files_indexed": 1820, "chunks": 40211},
		"backup":       map[string]any{"state": "no_key", "key_present": false},
		"update":       map[string]any{"current_version": "0.1.0", "state": "idle"},
		"applied_schedules": []map[string]any{
			{"id": "nightly-sync", "job": "vectorize_sync", "every": "daily", "hour": 2, "minute": 30, "enabled": true},
			{"id": "weekly-backup", "job": "backup_run", "every": "weekly", "weekday": 6, "hour": 3, "minute": 0, "enabled": false},
		},
	}
	if mod != nil {
		mod(m)
	}
	raw, _ := json.Marshal(m)
	return helper.Response{OK: true, Result: raw}
}

func TestApplianceStatusPrintsAReadableSummary(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(f.stateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(f.stateDir, agent.SchedulesFileName),
		[]byte(`{"schedules":{"nightly-sync":{"last_run_at":"2026-10-02T00:30:00Z","last_status":"ok"}}}`), 0o600)
	token := "hmd_0123456789abcdef0123456789abcdef.Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF"
	var socket string
	f.env.HelperStatus = func(_ context.Context, s string) (helper.Response, error) {
		socket = s
		return statusResult(t, func(m map[string]any) { m["apply_detail"] = "leaked " + token }), nil
	}
	if code := f.run("appliance", "status"); code != ExitOK {
		t.Fatalf("%d %s", code, f.output())
	}
	out := f.stdout.String()
	for _, want := range []string{
		"Control:      cloud", "Mode:         private_ai", "revision 12, partial",
		"plugins yes, nas yes, backup no, update yes", "hmk1.", "ollama 1",
		"ollama         running", "11434", "docs           error", "nas.docs.password", "ok",
		"1820 indexed", "no_key", "nightly-sync", "02:30", "last 2026-10-02T00:30:00Z ok", "Sun 03:00", "disabled",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, token) || !strings.Contains(out, "[REDACTED") {
		t.Fatalf("a credential in a detail must be redacted:\n%s", out)
	}
	if socket != "/run/happymining-helper.sock" {
		t.Fatalf("socket %q", socket)
	}
	if code := f.run("appliance", "status", "--json"); code != ExitOK {
		t.Fatalf("%d %s", code, f.output())
	}
	var rep map[string]any
	if err := json.Unmarshal(f.stdout.Bytes(), &rep); err != nil || rep["applied_revision"] != float64(12) {
		t.Fatalf("json: %v %s", err, f.stdout.String())
	}
	if len(rep["applied_schedules"].([]any)) != 2 {
		t.Fatalf("json schedules: %v", rep["applied_schedules"])
	}
}

func TestApplianceStatusExplainsWhenTheHelperCannotAnswer(t *testing.T) {
	f := newFixture(t)
	cases := map[string]func(context.Context, string) (helper.Response, error){
		"sudo": func(context.Context, string) (helper.Response, error) {
			return helper.Response{}, errors.New("privileged helper is not available: dial unix /run/happymining-helper.sock: connect: permission denied")
		},
		"not reachable": func(context.Context, string) (helper.Response, error) {
			return helper.Response{}, helper.ErrUnavailable
		},
		"only answers root": func(context.Context, string) (helper.Response, error) {
			return helper.Response{Code: agent.CodeUnauthorized, Detail: "peer is not allowed"}, nil
		},
		"refused (invalid)": func(context.Context, string) (helper.Response, error) {
			return helper.Response{Code: agent.CodeInvalid, Detail: "unknown action"}, nil
		},
		"does not understand": func(context.Context, string) (helper.Response, error) {
			return helper.Response{OK: true, Result: json.RawMessage(`[1]`)}, nil
		},
	}
	for want, fn := range cases {
		f.env.HelperStatus = fn
		if code := f.run("appliance", "status"); code != ExitFail || !strings.Contains(f.stderr.String(), want) {
			t.Errorf("%s: %d %s", want, code, f.output())
		}
	}
}

func TestUsageListsTheNewCommands(t *testing.T) {
	f := newFixture(t)
	f.run("help")
	for _, want := range []string{"appliance", "backup"} {
		if !strings.Contains(f.output(), want) {
			t.Errorf("usage lacks %q", want)
		}
	}
	if code := f.run("appliance", "help"); code != ExitOK || !strings.Contains(f.stdout.String(), "secret set") {
		t.Fatalf("%d %s", code, f.output())
	}
}
