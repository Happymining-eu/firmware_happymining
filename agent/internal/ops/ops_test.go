package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/client"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/logx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/redact"
)

const (
	token   = "hmd_0123456789abcdef0123456789abcdef.Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF"
	pairing = "HM-7K2M9Q-4F8T-ZP3D-W6NH-R5XA"
	nonce   = "c29tZS1yYW5kb20tbm9uY2UtMTIz"
)

type fakeExec struct {
	calls     []string
	failWith  error
	result    any
	detail    string
	journalAt func() bool // reports whether the id is already journaled when executing
	// install_update: the start error, and the completion of the last start.
	installStartErr error
	installDone     func(string, error)
}

func (f *fakeExec) record(name string) (string, error) {
	f.calls = append(f.calls, name)
	if f.journalAt != nil && !f.journalAt() {
		return "", errors.New("executed before being journaled")
	}
	if f.failWith != nil {
		return "", f.failWith
	}
	if f.detail != "" {
		return f.detail, nil
	}
	return name + " done", nil
}

func (f *fakeExec) RefreshInventory(context.Context) (string, error) {
	return f.record("refresh_inventory")
}
func (f *fakeExec) CollectDiagnostics(_ context.Context, sections []string) (any, error) {
	_, err := f.record("collect_diagnostics:" + strings.Join(sections, ","))
	return f.result, err
}
func (f *fakeExec) RunPreflight(context.Context) (string, any, error) {
	d, err := f.record("run_preflight")
	return d, f.result, err
}
func (f *fakeExec) RotateCredential(context.Context) (string, error) {
	return f.record("rotate_credential")
}
func (f *fakeExec) RestartVastDaemon(context.Context) (string, error) {
	return f.record("restart_vast_daemon")
}
func (f *fakeExec) Reboot(_ context.Context, delay int) (string, error) {
	return f.record(fmt.Sprintf("reboot:%d", delay))
}
func (f *fakeExec) ApplianceRunJob(_ context.Context, job, plugin string) (string, error) {
	return f.record("appliance_run_job:" + job + ":" + plugin)
}
func (f *fakeExec) InstallUpdate(_ context.Context, version string, done func(string, error)) error {
	f.calls = append(f.calls, "install_update:"+version)
	if f.journalAt != nil && !f.journalAt() {
		return errors.New("executed before being journaled")
	}
	if f.installStartErr != nil {
		return f.installStartErr
	}
	f.installDone = done
	return nil
}

type fakeAcker struct {
	acks []protocol.AckRequest
	ids  []string
	err  error
}

func (f *fakeAcker) Ack(_ context.Context, id string, ack *protocol.AckRequest) error {
	f.ids = append(f.ids, id)
	f.acks = append(f.acks, *ack)
	return f.err
}

func (f *fakeAcker) last() protocol.AckRequest { return f.acks[len(f.acks)-1] }

type fixture struct {
	h       *Handler
	exec    *fakeExec
	acker   *fakeAcker
	journal *Journal
	path    string
	now     time.Time
	logs    *bytes.Buffer
}

func newFixture(t *testing.T, optIn ...string) *fixture {
	t.Helper()
	f := &fixture{exec: &fakeExec{}, acker: &fakeAcker{}, now: time.Date(2026, 10, 2, 7, 45, 0, 0, time.UTC), logs: &bytes.Buffer{}}
	f.path = filepath.Join(t.TempDir(), JournalFileName)
	j, err := OpenJournal(f.path, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	f.journal = j
	r := redact.New()
	f.h = NewHandler(j, f.exec, f.acker, r, logx.New(f.logs, slog.LevelDebug, r), func() time.Time { return f.now }, optIn)
	return f
}

var idCounter int

func (f *fixture) op(opType, params string) protocol.Operation {
	idCounter++
	op := protocol.Operation{
		ID:        fmt.Sprintf("00000000-0000-4000-8000-%012d", idCounter),
		Type:      opType,
		IssuedAt:  protocol.FormatTime(f.now),
		ExpiresAt: protocol.FormatTime(f.now.Add(10 * time.Minute)),
		Nonce:     nonce,
	}
	if params != "" {
		op.Params = json.RawMessage(params)
	}
	return op
}

func TestDefaultEnabledOperationsRun(t *testing.T) {
	f := newFixture(t)
	f.exec.result = map[string]any{"services": map[string]string{"docker": "active"}}
	cases := map[string]protocol.Operation{
		"refresh_inventory":                f.op("refresh_inventory", `{}`),
		"collect_diagnostics:services,gpu": f.op("collect_diagnostics", `{"sections":["services","gpu"]}`),
		"run_preflight":                    f.op("run_preflight", ""),
		"rotate_credential":                f.op("rotate_credential", `null`),
	}
	for wantCall, op := range cases {
		before := len(f.exec.calls)
		if status := f.h.Handle(context.Background(), op); status != protocol.AckSucceeded {
			t.Fatalf("%s: status %q, ack %+v", op.Type, status, f.acker.last())
		}
		if len(f.exec.calls) != before+1 || f.exec.calls[before] != wantCall {
			t.Fatalf("%s: calls %v", op.Type, f.exec.calls)
		}
		ack := f.acker.last()
		if ack.Status != protocol.AckSucceeded || ack.Nonce != nonce || ack.CompletedAt != "2026-10-02T07:45:00Z" {
			t.Fatalf("%s: ack %+v", op.Type, ack)
		}
		if !json.Valid(ack.Result) {
			t.Fatalf("result is not JSON: %s", ack.Result)
		}
	}
}

func TestUnknownTypeIsRejected(t *testing.T) {
	f := newFixture(t)
	for _, opType := range []string{"run_shell", "", "REBOOT", "exec", "refresh_inventory "} {
		if status := f.h.Handle(context.Background(), f.op(opType, `{"cmd":"id"}`)); status != protocol.AckRejected {
			t.Errorf("%q: status %q", opType, status)
		}
		if ack := f.acker.last(); ack.Status != protocol.AckRejected || ack.Nonce != nonce || !strings.Contains(ack.Detail, "unknown operation type") {
			t.Errorf("%q: ack %+v", opType, ack)
		}
	}
	if len(f.exec.calls) != 0 {
		t.Fatalf("nothing may execute: %v", f.exec.calls)
	}
}

func TestBadParamsAreRejected(t *testing.T) {
	f := newFixture(t, "reboot", "restart_vast_daemon")
	cases := []struct{ opType, params string }{
		{"refresh_inventory", `{"extra":1}`},
		{"refresh_inventory", `[]`},
		{"refresh_inventory", `"x"`},
		{"refresh_inventory", `{} {}`},
		{"run_preflight", `{"command":"rm -rf /"}`},
		{"rotate_credential", `{"token":"x"}`},
		{"restart_vast_daemon", `{"unit":"ssh"}`},
		{"collect_diagnostics", `{}`},
		{"collect_diagnostics", `{"sections":[]}`},
		{"collect_diagnostics", `{"sections":["processes"]}`},
		{"collect_diagnostics", `{"sections":["gpu","gpu"]}`},
		{"collect_diagnostics", `{"sections":"gpu"}`},
		{"collect_diagnostics", `{"sections":["gpu"],"path":"/etc/shadow"}`},
		{"reboot", `{}`},
		{"reboot", `{"delay_s":59}`},
		{"reboot", `{"delay_s":3601}`},
		{"reboot", `{"delay_s":0}`},
		{"reboot", `{"delay_s":-60}`},
		{"reboot", `{"delay_s":"120"}`},
		{"reboot", `{"delay_s":120.5}`},
		{"reboot", `{"delay_s":120,"force":true}`},
		{"reboot", `{"delay_s":null}`},
	}
	for _, tc := range cases {
		if status := f.h.Handle(context.Background(), f.op(tc.opType, tc.params)); status != protocol.AckRejected {
			t.Errorf("%s %s: status %q", tc.opType, tc.params, status)
		}
		if ack := f.acker.last(); !strings.Contains(ack.Detail, "invalid params") {
			t.Errorf("%s %s: detail %q", tc.opType, tc.params, ack.Detail)
		}
	}
	if len(f.exec.calls) != 0 {
		t.Fatalf("nothing may execute: %v", f.exec.calls)
	}
}

func TestExpiredAndBadTimestampsAreRejected(t *testing.T) {
	f := newFixture(t)
	expired := f.op("refresh_inventory", `{}`)
	expired.ExpiresAt = protocol.FormatTime(f.now.Add(-time.Second))
	exact := f.op("refresh_inventory", `{}`)
	exact.ExpiresAt = protocol.FormatTime(f.now)
	noExpiry := f.op("refresh_inventory", `{}`)
	noExpiry.ExpiresAt = ""
	badExpiry := f.op("refresh_inventory", `{}`)
	badExpiry.ExpiresAt = "tomorrow"
	badIssued := f.op("refresh_inventory", `{}`)
	badIssued.IssuedAt = "yesterday"
	cases := []struct {
		name   string
		op     protocol.Operation
		detail string
	}{
		{"expired", expired, "operation expired"},
		{"expires now", exact, "operation expired"},
		{"no expiry", noExpiry, "invalid expires_at"},
		{"bad expiry", badExpiry, "invalid expires_at"},
		{"bad issued_at", badIssued, "invalid issued_at"},
	}
	for _, tc := range cases {
		if status := f.h.Handle(context.Background(), tc.op); status != protocol.AckRejected {
			t.Errorf("%s: status %q", tc.name, status)
		}
		if got := f.acker.last().Detail; got != tc.detail {
			t.Errorf("%s: detail %q, want %q", tc.name, got, tc.detail)
		}
	}
	if len(f.exec.calls) != 0 {
		t.Fatalf("nothing may execute: %v", f.exec.calls)
	}
}

func TestDisabledByDefaultTypesAreRejected(t *testing.T) {
	f := newFixture(t) // no opt-in
	for _, op := range []protocol.Operation{f.op("restart_vast_daemon", `{}`), f.op("reboot", `{"delay_s":120}`)} {
		if status := f.h.Handle(context.Background(), op); status != protocol.AckRejected {
			t.Errorf("%s: status %q", op.Type, status)
		}
		if ack := f.acker.last(); !strings.Contains(ack.Detail, "disabled by local configuration") {
			t.Errorf("%s: detail %q", op.Type, ack.Detail)
		}
	}
	if len(f.exec.calls) != 0 {
		t.Fatalf("nothing may execute: %v", f.exec.calls)
	}
}

func TestOptInOperationsRunThroughTheExecutor(t *testing.T) {
	f := newFixture(t, "reboot", "restart_vast_daemon")
	if status := f.h.Handle(context.Background(), f.op("reboot", `{"delay_s":120}`)); status != protocol.AckSucceeded {
		t.Fatalf("status %q", status)
	}
	if status := f.h.Handle(context.Background(), f.op("restart_vast_daemon", `{}`)); status != protocol.AckSucceeded {
		t.Fatalf("status %q", status)
	}
	if fmt.Sprint(f.exec.calls) != "[reboot:120 restart_vast_daemon]" {
		t.Fatalf("calls: %v", f.exec.calls)
	}
	// accepted (starting) then succeeded, for each of the two.
	var statuses []string
	for _, a := range f.acker.acks {
		statuses = append(statuses, a.Status)
	}
	if fmt.Sprint(statuses) != "[accepted succeeded accepted succeeded]" {
		t.Fatalf("acks: %v", statuses)
	}
}

func TestNotImplementedTypesNeverFakeSuccess(t *testing.T) {
	// Even when the local administrator opted in.
	f := newFixture(t, "run_benchmark", "apply_hardware_profile")
	for _, op := range []protocol.Operation{f.op("run_benchmark", `{"duration_s":60}`), f.op("apply_hardware_profile", `{"profile_id":"eco"}`)} {
		if status := f.h.Handle(context.Background(), op); status != protocol.AckRejected {
			t.Errorf("%s: status %q", op.Type, status)
		}
		if ack := f.acker.last(); ack.Detail != "not implemented in this agent version" {
			t.Errorf("%s: detail %q", op.Type, ack.Detail)
		}
	}
	if len(f.exec.calls) != 0 {
		t.Fatalf("nothing may execute: %v", f.exec.calls)
	}
}

func TestReplayedIDIsNeverExecutedTwice(t *testing.T) {
	f := newFixture(t)
	op := f.op("refresh_inventory", `{}`)
	if status := f.h.Handle(context.Background(), op); status != protocol.AckSucceeded {
		t.Fatalf("first: %q", status)
	}
	for i := 0; i < 3; i++ {
		f.h.Handle(context.Background(), op)
	}
	if len(f.exec.calls) != 1 {
		t.Fatalf("executed %d times", len(f.exec.calls))
	}
	if ack := f.acker.last(); ack.Status != protocol.AckSucceeded || !strings.Contains(ack.Detail, "replayed operation id") || ack.Nonce != nonce {
		t.Fatalf("replay ack: %+v", ack)
	}

	// The same id with a different type or params is still a replay.
	other := op
	other.Type, other.Params = "collect_diagnostics", json.RawMessage(`{"sections":["gpu"]}`)
	f.h.Handle(context.Background(), other)
	if len(f.exec.calls) != 1 {
		t.Fatal("a replayed id with another type was executed")
	}

	// A rejected id stays rejected, even if it would now be valid.
	rejected := f.op("refresh_inventory", `{"bad":1}`)
	f.h.Handle(context.Background(), rejected)
	rejected.Params = json.RawMessage(`{}`)
	if status := f.h.Handle(context.Background(), rejected); status != protocol.AckRejected {
		t.Fatalf("a previously rejected id must not run: %q", status)
	}
	if len(f.exec.calls) != 1 {
		t.Fatal("a previously rejected id was executed")
	}
}

func TestReplayProtectionSurvivesRestart(t *testing.T) {
	f := newFixture(t)
	op := f.op("refresh_inventory", `{}`)
	f.h.Handle(context.Background(), op)
	_ = f.journal.Close()

	// "Restart": a new journal instance on the same file.
	j, err := OpenJournal(f.path, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	exec, acker := &fakeExec{}, &fakeAcker{}
	r := redact.New()
	h := NewHandler(j, exec, acker, r, logx.Discard(), func() time.Time { return f.now }, nil)
	if status := h.Handle(context.Background(), op); status != protocol.AckSucceeded {
		t.Fatalf("the recorded outcome must be acknowledged again, got %q", status)
	}
	if len(exec.calls) != 0 {
		t.Fatal("replayed after restart")
	}
}

func TestInterruptedOperationIsNotExecutedAgain(t *testing.T) {
	f := newFixture(t, "reboot")
	op := f.op("reboot", `{"delay_s":60}`)
	// Simulate a crash (or the reboot itself) after journaling, before the
	// outcome was recorded.
	exp, _ := time.Parse(time.RFC3339, op.ExpiresAt)
	if err := f.journal.Start(op.ID, op.Type, exp); err != nil {
		t.Fatal(err)
	}
	_ = f.journal.Close()
	j, _ := OpenJournal(f.path, func() time.Time { return f.now })
	exec, acker := &fakeExec{}, &fakeAcker{}
	r := redact.New()
	h := NewHandler(j, exec, acker, r, logx.Discard(), func() time.Time { return f.now }, []string{"reboot"})
	if status := h.Handle(context.Background(), op); status != protocol.AckRejected {
		t.Fatalf("status %q", status)
	}
	if len(exec.calls) != 0 {
		t.Fatal("a reboot whose outcome is unknown must not be executed again (reboot loop)")
	}
}

func TestJournaledBeforeExecution(t *testing.T) {
	f := newFixture(t)
	op := f.op("refresh_inventory", `{}`)
	f.exec.journalAt = func() bool {
		// Read the file as another process would: the id must be on disk.
		data, _ := os.ReadFile(f.path)
		return bytes.Contains(data, []byte(op.ID))
	}
	if status := f.h.Handle(context.Background(), op); status != protocol.AckSucceeded {
		t.Fatalf("status %q: %+v", status, f.acker.last())
	}
}

func TestJournalFailureMeansNoExecution(t *testing.T) {
	f := newFixture(t)
	_ = f.journal.Close() // appending now fails
	f.journal.f, _ = os.Open(f.path)
	if status := f.h.Handle(context.Background(), f.op("refresh_inventory", `{}`)); status != protocol.AckRejected {
		t.Fatalf("status %q", status)
	}
	if len(f.exec.calls) != 0 {
		t.Fatal("executed without a journal record")
	}
}

func TestInvalidIDsAndNonces(t *testing.T) {
	f := newFixture(t)
	op := f.op("refresh_inventory", `{}`)
	op.ID = "../../etc/passwd"
	if status := f.h.Handle(context.Background(), op); status != "" || len(f.acker.acks) != 0 {
		t.Fatalf("an operation with an unusable id must be ignored: %q %v", status, f.acker.acks)
	}
	for _, bad := range []string{"", "short", strings.Repeat("a", 300), "has spaces in the nonce value!!"} {
		op := f.op("refresh_inventory", `{}`)
		op.Nonce = bad
		if status := f.h.Handle(context.Background(), op); status != protocol.AckRejected {
			t.Errorf("nonce %q: status %q", bad, status)
		}
		if f.acker.last().Nonce != "" {
			t.Errorf("an invalid nonce must not be echoed: %q", f.acker.last().Nonce)
		}
	}
	if len(f.exec.calls) != 0 {
		t.Fatalf("nothing may execute: %v", f.exec.calls)
	}
}

func TestFailureIsReportedAsFailed(t *testing.T) {
	f := newFixture(t)
	f.exec.failWith = errors.New("disk on fire")
	if status := f.h.Handle(context.Background(), f.op("run_preflight", `{}`)); status != protocol.AckFailed {
		t.Fatalf("status %q", status)
	}
	if ack := f.acker.last(); ack.Status != protocol.AckFailed || ack.Detail != "disk on fire" || string(ack.Result) != "{}" {
		t.Fatalf("ack %+v", ack)
	}
}

func TestResultsAndDetailsAreRedactedAndBounded(t *testing.T) {
	f := newFixture(t)
	f.exec.detail = "done with Bearer " + token + " and code " + pairing + " " + strings.Repeat("x", 5000)
	f.exec.result = map[string]any{
		"note":  "Authorization: Bearer " + token,
		"token": token,
		"deep":  []any{map[string]any{"pairing_code": pairing, "text": "typed hm 7k2m9q 4f8t zp3d w6nh r5xa"}},
	}
	f.h.Handle(context.Background(), f.op("run_preflight", `{}`))
	ack := f.acker.last()
	all := ack.Detail + string(ack.Result) + f.logs.String()
	journal, _ := os.ReadFile(f.path)
	all += string(journal)
	for _, leak := range []string{token, "Zm9vYmFyYmF6cXV4", "7K2M9Q", "7k2m9q", "R5XA"} {
		if strings.Contains(all, leak) {
			t.Errorf("leak of %q", leak)
		}
	}
	if len([]rune(ack.Detail)) > protocol.MaxDetailLen {
		t.Fatalf("detail has %d characters", len([]rune(ack.Detail)))
	}

	f.exec.detail = ""
	f.exec.result = map[string]any{"big": strings.Repeat("y", 100*1024)}
	f.h.Handle(context.Background(), f.op("run_preflight", `{}`))
	ack = f.acker.last()
	if len(ack.Result) > protocol.MaxResultBytes || !strings.Contains(string(ack.Result), "truncated") {
		t.Fatalf("oversized result not bounded: %d bytes", len(ack.Result))
	}
}

func TestHandleAllBoundsTheBatch(t *testing.T) {
	f := newFixture(t)
	var batch []protocol.Operation
	for i := 0; i < MaxPerResponse+10; i++ {
		batch = append(batch, f.op("refresh_inventory", `{}`))
	}
	f.h.HandleAll(context.Background(), batch)
	if len(f.exec.calls) != MaxPerResponse {
		t.Fatalf("handled %d operations, want %d", len(f.exec.calls), MaxPerResponse)
	}
}

func TestAckErrorsDoNotStopHandling(t *testing.T) {
	f := newFixture(t)
	f.acker.err = &client.APIError{Status: 409, Code: "conflict"}
	if status := f.h.Handle(context.Background(), f.op("refresh_inventory", `{}`)); status != protocol.AckSucceeded {
		t.Fatalf("status %q", status)
	}
	f.acker.err = errors.New("network down")
	if status := f.h.Handle(context.Background(), f.op("refresh_inventory", `{}`)); status != protocol.AckSucceeded {
		t.Fatalf("status %q", status)
	}
}

func TestJournalPruning(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	path := filepath.Join(t.TempDir(), JournalFileName)
	j, err := OpenJournal(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	old := "00000000-0000-4000-8000-000000000001"
	longLived := "00000000-0000-4000-8000-000000000002"
	if err := j.Start(old, "refresh_inventory", now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	_ = j.Finish(old, protocol.AckSucceeded, "ok")
	// An operation that stays valid for 60 days must outlive the 30-day retention.
	if err := j.Start(longLived, "refresh_inventory", now.Add(60*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := j.Start(old, "x", now); err == nil {
		t.Fatal("a duplicate Start must fail")
	}

	now = now.Add(29 * 24 * time.Hour)
	if err := j.Prune(); err != nil {
		t.Fatal(err)
	}
	if _, ok := j.Lookup(old); !ok {
		t.Fatal("pruned before the retention period")
	}
	now = now.Add(2 * 24 * time.Hour) // day 31
	if err := j.Prune(); err != nil {
		t.Fatal(err)
	}
	if _, ok := j.Lookup(old); ok {
		t.Fatal("an entry older than 30 days must be pruned")
	}
	if _, ok := j.Lookup(longLived); !ok {
		t.Fatal("an entry whose operation has not expired must never be pruned (replay window)")
	}
	_ = j.Close()

	j2, err := OpenJournal(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := j2.Lookup(longLived); !ok || j2.Len() != 1 {
		t.Fatalf("after reopen: %d entries", j2.Len())
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode %04o", fi.Mode().Perm())
	}
}

func TestJournalToleratesTornLastLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), JournalFileName)
	j, _ := OpenJournal(path, nil)
	id := "00000000-0000-4000-8000-000000000009"
	_ = j.Start(id, "refresh_inventory", time.Now().Add(time.Hour))
	_ = j.Close()
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"at":"2026-10-02T00:00:00Z","event":"start","id":"0000`)
	_ = f.Close()
	j2, err := OpenJournal(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := j2.Lookup(id); !ok || j2.Len() != 1 {
		t.Fatalf("complete entries must survive a torn line: %d", j2.Len())
	}
}
