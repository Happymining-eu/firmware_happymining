package ops

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/logx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/redact"
)

func TestApplianceOperationsAreEnabledByDefault(t *testing.T) {
	f := newFixture(t)
	enabled := strings.Join(f.h.EnabledTypes(), ",")
	for _, want := range []string{protocol.OpApplianceRunJob, protocol.OpInstallUpdate} {
		if !f.h.Enabled(want) || !strings.Contains(enabled, want) {
			t.Errorf("%s must be enabled without local opt-in (its gate is the helper switch): %s", want, enabled)
		}
	}
	// The disruptive types stay disabled.
	for _, off := range []string{protocol.OpRestartVastDaemon, protocol.OpReboot} {
		if f.h.Enabled(off) {
			t.Errorf("%s must stay disabled by default", off)
		}
	}
}

func TestApplianceRunJobReachesTheExecutor(t *testing.T) {
	f := newFixture(t)
	cases := map[string]string{
		`{"job":"vectorize_sync"}`:                       "appliance_run_job:vectorize_sync:",
		`{"job":"backup_run"}`:                           "appliance_run_job:backup_run:",
		`{"job":"update_check"}`:                         "appliance_run_job:update_check:",
		`{"job":"plugin_restart","plugin":"ollama"}`:     "appliance_run_job:plugin_restart:ollama",
		`{"plugin":"open-webui","job":"plugin_restart"}`: "appliance_run_job:plugin_restart:open-webui",
	}
	for params, want := range cases {
		before := len(f.exec.calls)
		if status := f.h.Handle(context.Background(), f.op(protocol.OpApplianceRunJob, params)); status != protocol.AckSucceeded {
			t.Fatalf("%s: status %q, ack %+v", params, status, f.acker.last())
		}
		if len(f.exec.calls) != before+1 || f.exec.calls[before] != want {
			t.Fatalf("%s: calls %v, want %s", params, f.exec.calls, want)
		}
		// One final acknowledgement, no "accepted" first: the job is started, not awaited.
		if f.acker.last().Status != protocol.AckSucceeded {
			t.Fatalf("%s: ack %+v", params, f.acker.last())
		}
	}
}

func TestApplianceRunJobParamsAreStrict(t *testing.T) {
	f := newFixture(t)
	for _, params := range []string{
		`{}`,
		`null`,
		`[]`,
		`{"job":"shell"}`,
		`{"job":"Backup_run"}`,
		`{"job":["backup_run"]}`,
		`{"job":null}`,
		`{"job":"backup_run","plugin":"ollama"}`,
		`{"job":"backup_run","plugin":null}`,
		`{"job":"backup_run","extra":1}`,
		`{"job":"plugin_restart"}`,
		`{"job":"plugin_restart","plugin":null}`,
		`{"job":"plugin_restart","plugin":"Ollama"}`,
		`{"job":"plugin_restart","plugin":"../x"}`,
		`{"job":"plugin_restart","plugin":"a-very-long-plugin-identifier-beyond"}`,
		`{"job":"plugin_restart","plugin":7}`,
		`{"job":"plugin_restart","plugin":"ollama","extra":true}`,
		`{"job":"backup_run"} {"job":"backup_run"}`,
	} {
		status := f.h.Handle(context.Background(), f.op(protocol.OpApplianceRunJob, params))
		if status != protocol.AckRejected || !strings.Contains(f.acker.last().Detail, "invalid params") {
			t.Errorf("%s: status %q detail %q, want rejected as invalid params", params, status, f.acker.last().Detail)
		}
	}
	if len(f.exec.calls) != 0 {
		t.Fatalf("invalid params reached the executor: %v", f.exec.calls)
	}
}

func TestInstallUpdateParamsAreStrict(t *testing.T) {
	f := newFixture(t)
	for _, params := range []string{
		`{}`, `null`, `{"version":null}`, `{"version":1}`, `{"version":"1.2"}`, `{"version":"01.2.3"}`,
		`{"version":"1.2.3-rc1"}`, `{"version":" 1.2.3"}`, `{"version":"1.2.3","channel":"beta"}`,
		`{"version":"1234567.0.0"}`, `{"version":"../../etc"}`,
	} {
		status := f.h.Handle(context.Background(), f.op(protocol.OpInstallUpdate, params))
		if status != protocol.AckRejected {
			t.Errorf("%s: status %q, want rejected", params, status)
		}
	}
	if len(f.exec.calls) != 0 {
		t.Fatalf("invalid params reached the executor: %v", f.exec.calls)
	}
}

func TestInstallUpdateIsAcceptedThenFinishedOnce(t *testing.T) {
	f := newFixture(t)
	op := f.op(protocol.OpInstallUpdate, `{"version":"0.2.0"}`)
	f.exec.journalAt = func() bool { _, ok := f.journal.Lookup(op.ID); return ok }
	if status := f.h.Handle(context.Background(), op); status != protocol.AckAccepted {
		t.Fatalf("status %q, ack %+v", status, f.acker.last())
	}
	if len(f.exec.calls) != 1 || f.exec.calls[0] != "install_update:0.2.0" {
		t.Fatalf("calls %v", f.exec.calls)
	}
	if len(f.acker.acks) != 1 || f.acker.acks[0].Status != protocol.AckAccepted || f.acker.acks[0].Nonce != nonce {
		t.Fatalf("first acknowledgement must be accepted with the nonce: %+v", f.acker.acks)
	}
	if rec, _ := f.journal.Lookup(op.ID); rec.Final != "" {
		t.Fatalf("no final outcome before the flow finished: %+v", rec)
	}
	// The flow finishes later, on the loop goroutine.
	f.exec.installDone("update handed to the helper", nil)
	if len(f.acker.acks) != 2 || f.acker.last().Status != protocol.AckSucceeded || f.acker.last().Nonce != nonce {
		t.Fatalf("acks %+v", f.acker.acks)
	}
	if rec, _ := f.journal.Lookup(op.ID); rec.Final != protocol.AckSucceeded {
		t.Fatalf("journal %+v", rec)
	}
	// A second completion is ignored: exactly one final outcome.
	f.exec.installDone("again", errors.New("late failure"))
	if len(f.acker.acks) != 2 {
		t.Fatalf("a second completion was acknowledged: %+v", f.acker.acks)
	}
	// Replayed later: never started again, the recorded outcome is repeated.
	if status := f.h.Handle(context.Background(), op); status != protocol.AckSucceeded || len(f.exec.calls) != 1 {
		t.Fatalf("replay: %q %v", status, f.exec.calls)
	}
}

func TestInstallUpdateRepeatedWhileRunningIsAcceptedAgainNotRejected(t *testing.T) {
	f := newFixture(t)
	op := f.op(protocol.OpInstallUpdate, `{"version":"0.2.0"}`)
	f.h.Handle(context.Background(), op)
	// The server did not get the "accepted" and sends the operation again.
	if status := f.h.Handle(context.Background(), op); status != protocol.AckAccepted {
		t.Fatalf("status %q: an operation that is still running must not be rejected", status)
	}
	if len(f.exec.calls) != 1 || f.acker.last().Status != protocol.AckAccepted {
		t.Fatalf("calls %v ack %+v", f.exec.calls, f.acker.last())
	}
	f.exec.installDone("done", nil)
	if f.acker.last().Status != protocol.AckSucceeded {
		t.Fatalf("ack %+v", f.acker.last())
	}
}

func TestInstallUpdateFailureIsReportedAsFailed(t *testing.T) {
	f := newFixture(t)
	op := f.op(protocol.OpInstallUpdate, `{"version":"0.2.0"}`)
	if status := f.h.Handle(context.Background(), op); status != protocol.AckAccepted {
		t.Fatalf("status %q", status)
	}
	f.exec.installDone("", errors.New("the package does not match the manifest"))
	if f.acker.last().Status != protocol.AckFailed || !strings.Contains(f.acker.last().Detail, "does not match") {
		t.Fatalf("ack %+v", f.acker.last())
	}

	// Refused before anything started: failed at once.
	f.exec.installStartErr = errors.New("another update is in progress")
	op2 := f.op(protocol.OpInstallUpdate, `{"version":"0.2.0"}`)
	if status := f.h.Handle(context.Background(), op2); status != protocol.AckFailed {
		t.Fatalf("status %q", status)
	}
	if rec, _ := f.journal.Lookup(op2.ID); rec.Final != protocol.AckFailed {
		t.Fatalf("journal %+v", rec)
	}
}

func TestInstallUpdateInterruptedIsNotRunAgain(t *testing.T) {
	f := newFixture(t)
	op := f.op(protocol.OpInstallUpdate, `{"version":"0.2.0"}`)
	if status := f.h.Handle(context.Background(), op); status != protocol.AckAccepted {
		t.Fatalf("status %q", status)
	}
	// The agent restarts before the flow finished: the journal has the start only.
	if err := f.journal.Close(); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(f.path, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	exec, acker := &fakeExec{}, &fakeAcker{}
	r := redact.New()
	h := NewHandler(j, exec, acker, r, logx.Discard(), func() time.Time { return f.now }, nil)
	if status := h.Handle(context.Background(), op); status != protocol.AckRejected {
		t.Fatalf("status %q", status)
	}
	if len(exec.calls) != 0 || !strings.Contains(acker.last().Detail, "not executed again") {
		t.Fatalf("calls %v ack %+v", exec.calls, acker.last())
	}
}
