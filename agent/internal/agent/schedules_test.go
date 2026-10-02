package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/helper"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/testapi"
)

func paris(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Skip("time zone data not available:", err)
	}
	return loc
}

func ip(v int) *int { return &v }

func daily(id string, hour, minute int) appliance.Schedule {
	return appliance.Schedule{ID: id, Job: appliance.JobVectorizeSync, Every: "daily", Hour: ip(hour), Minute: minute, Enabled: true}
}

func TestSchedulerRunsOnceAtLocalTimeWithoutCatchUp(t *testing.T) {
	loc := paris(t)
	s, err := newScheduler(t.TempDir(), loc)
	if err != nil {
		t.Fatal(err)
	}
	// 01:00 Paris time; the job is at 02:30 local.
	now := time.Date(2026, 10, 2, 1, 0, 0, 0, loc)
	s.setSchedules([]appliance.Schedule{daily("nightly", 2, 30)}, now)
	want := time.Date(2026, 10, 2, 2, 30, 0, 0, loc)
	if got := s.report()[0].NextRunAt; got != appliance.FormatTime(want) {
		t.Fatalf("next run %s, want %s (UTC %s)", got, want, appliance.FormatTime(want))
	}
	if run, _ := s.due(want.Add(-time.Second)); len(run) != 0 {
		t.Fatal("ran early")
	}
	run, missed := s.due(want.Add(10 * time.Second))
	if len(run) != 1 || len(missed) != 0 {
		t.Fatalf("run %v missed %v", run, missed)
	}
	// Due once only, even when asked again at the same moment.
	if run, _ := s.due(want.Add(20 * time.Second)); len(run) != 0 {
		t.Fatal("ran twice")
	}
	if got := s.report()[0].NextRunAt; got != appliance.FormatTime(want.AddDate(0, 0, 1)) {
		t.Fatalf("next after run: %s", got)
	}
	// The machine was off for two days: the runs in between are not caught
	// up, the late one is dropped and the next is computed from now.
	later := want.AddDate(0, 0, 3).Add(3 * time.Hour)
	run, missed = s.due(later)
	if len(run) != 0 || len(missed) != 1 {
		t.Fatalf("a run hours late must be dropped: run %v missed %v", run, missed)
	}
	if got := s.report()[0].NextRunAt; got != appliance.FormatTime(time.Date(2026, 10, 6, 2, 30, 0, 0, loc)) {
		t.Fatalf("next after a missed run: %s", got)
	}
}

func TestSchedulerKeepsHistoryAcrossRestartButNotTheNextRun(t *testing.T) {
	loc := paris(t)
	dir := t.TempDir()
	s, _ := newScheduler(dir, loc)
	at := time.Date(2026, 10, 2, 2, 30, 0, 0, loc)
	s.setSchedules([]appliance.Schedule{daily("nightly", 2, 30)}, at.Add(-time.Hour))
	if err := s.record("nightly", appliance.RunFailed, at); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, SchedulesFileName))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("history file: %v %v", fi, err)
	}
	// Restart the next evening.
	s2, err := newScheduler(dir, loc)
	if err != nil {
		t.Fatal(err)
	}
	restart := time.Date(2026, 10, 3, 20, 0, 0, 0, loc)
	s2.setSchedules([]appliance.Schedule{daily("nightly", 2, 30)}, restart)
	rep := s2.report()[0]
	if rep.LastStatus != appliance.RunFailed || rep.LastRunAt != appliance.FormatTime(at) {
		t.Fatalf("history lost: %+v", rep)
	}
	if rep.NextRunAt != appliance.FormatTime(time.Date(2026, 10, 4, 2, 30, 0, 0, loc)) {
		t.Fatalf("next run must come from the restart time: %+v", rep)
	}
	if run, _ := s2.due(restart); len(run) != 0 {
		t.Fatal("caught up a run missed while the agent was down")
	}
}

func TestSchedulerChangedAndDisabledSchedules(t *testing.T) {
	loc := paris(t)
	s, _ := newScheduler(t.TempDir(), loc)
	now := time.Date(2026, 10, 2, 1, 0, 0, 0, loc)
	s.setSchedules([]appliance.Schedule{daily("a", 2, 30), daily("b", 3, 0)}, now)
	// Unchanged schedules keep their next run, a changed one is recomputed,
	// a disabled one has none and never runs, a removed one disappears.
	later := now.Add(10 * time.Minute)
	b := daily("b", 4, 15)
	off := daily("c", 1, 15)
	off.Enabled = false
	s.setSchedules([]appliance.Schedule{daily("a", 2, 30), b, off}, later)
	rep := s.report()
	if len(rep) != 3 || rep[0].NextRunAt != appliance.FormatTime(time.Date(2026, 10, 2, 2, 30, 0, 0, loc)) ||
		rep[1].NextRunAt != appliance.FormatTime(time.Date(2026, 10, 2, 4, 15, 0, 0, loc)) || rep[2].NextRunAt != "" {
		t.Fatalf("report: %+v", rep)
	}
	if run, _ := s.due(time.Date(2026, 10, 3, 1, 15, 0, 0, loc)); len(run) != 0 {
		for _, r := range run {
			if r.ID == "c" {
				t.Fatal("a disabled schedule ran")
			}
		}
	}
}

func TestSchedulerDaylightSavingTime(t *testing.T) {
	loc := paris(t)
	s, _ := newScheduler(t.TempDir(), loc)
	// Last Sunday of March 2027: 02:00 -> 03:00 in Paris. A 02:30 job runs at 03:00.
	before := time.Date(2027, 3, 27, 12, 0, 0, 0, loc)
	s.setSchedules([]appliance.Schedule{daily("nightly", 2, 30)}, before)
	want := time.Date(2027, 3, 28, 3, 0, 0, 0, loc)
	if got := s.report()[0].NextRunAt; got != appliance.FormatTime(want) {
		t.Fatalf("next run %s, want %s", got, appliance.FormatTime(want))
	}
}

func TestScheduledJobsAskTheHelperAndRecordTheOutcome(t *testing.T) {
	e := newEnv(t)
	loc := paris(t)
	clock := &fakeClock{t: time.Date(2026, 10, 2, 1, 0, 0, 0, loc)}
	status := cloudStatus(t)
	status["applied_schedules"] = []map[string]any{
		{"id": "sync", "job": "vectorize_sync", "every": "hourly", "minute": 5, "enabled": true},
		{"id": "backup", "job": "backup_run", "every": "hourly", "minute": 5, "enabled": true},
		{"id": "restart", "job": "plugin_restart", "plugin": "ollama", "every": "hourly", "minute": 5, "enabled": true},
	}
	fake := &fakeAppliance{status: status}
	a := e.agent(func(o *Options) { o.Appliance = fake; o.Now = clock.Now; o.Location = loc })
	a.reloadCredential()
	a.refreshApplianceStatus(context.Background())

	outcomes := []struct {
		resp *helper.Response
		err  error
		want string
	}{
		{nil, nil, appliance.RunOK},
		{&helper.Response{Code: CodeDisabled, Detail: "ALLOW_BACKUP is off"}, nil, appliance.RunSkipped},
		{&helper.Response{Code: CodeBusy, Detail: "still running"}, nil, appliance.RunSkipped},
		{&helper.Response{Code: CodeFailed, Detail: "systemctl failed"}, nil, appliance.RunFailed},
		{nil, errors.New("connection refused"), appliance.RunFailed},
	}
	for i, oc := range outcomes {
		fake.set(func(f *fakeAppliance) { f.runJob, f.runJobErr = oc.resp, oc.err })
		hour := time.Date(2026, 10, 2, 1+i, 5, 0, 0, loc)
		clock.Set(hour)
		before := len(fake.calls(ActionApplianceRunJob))
		a.runDueSchedules(context.Background(), clock.Now())
		calls := fake.calls(ActionApplianceRunJob)[before:]
		if len(calls) != 3 || calls[0].Job != "vectorize_sync" || calls[1].Job != "backup_run" ||
			calls[2].Job != "plugin_restart" || calls[2].Plugin != "ollama" || calls[0].Plugin != "" {
			t.Fatalf("hour %d: calls %+v", i, calls)
		}
		for _, st := range a.sched.report() {
			if st.LastStatus != oc.want || st.LastRunAt != appliance.FormatTime(hour) {
				t.Fatalf("hour %d: %+v, want %s", i, st, oc.want)
			}
		}
		// Not again within the same hour.
		clock.Add(30 * time.Second)
		a.runDueSchedules(context.Background(), clock.Now())
		if n := len(fake.calls(ActionApplianceRunJob)); n != before+3 {
			t.Fatalf("hour %d: started twice", i)
		}
	}
}

func TestScheduledUpdateCheckIsSkippedWhenUpdatesAreNotAllowed(t *testing.T) {
	e := newEnv(t)
	loc := paris(t)
	clock := &fakeClock{t: time.Date(2026, 10, 2, 1, 0, 0, 0, loc)}
	status := cloudStatus(t)
	status["capabilities"] = map[string]bool{"plugins": true, "nas": true, "backup": true, "update": false, "docker": true}
	status["applied_schedules"] = []map[string]any{
		{"id": "check", "job": "update_check", "every": "daily", "hour": 1, "minute": 10, "enabled": true},
	}
	fake := &fakeAppliance{status: status}
	a := e.agent(func(o *Options) { o.Appliance = fake; o.Now = clock.Now; o.Location = loc })
	a.reloadCredential()
	a.refreshApplianceStatus(context.Background())
	clock.Set(time.Date(2026, 10, 2, 1, 10, 0, 0, loc))
	a.runDueSchedules(context.Background(), clock.Now())
	if st := a.sched.report()[0]; st.LastStatus != appliance.RunSkipped {
		t.Fatalf("%+v", st)
	}
	if d := e.device(); d.UpdateRequests != 0 {
		t.Fatal("the API was asked although updates are not allowed")
	}
	if len(fake.calls(ActionApplianceRunJob)) != 0 {
		t.Fatal("update_check must not go to the helper as a job")
	}
}

func TestSchedulesRunDuringAnAPIOutage(t *testing.T) {
	e := newEnv(t)
	e.api.SetHeartbeatFault(func(int) *testapi.Fault { return &testapi.Fault{Status: 503} })
	status := cloudStatus(t)
	// One job for each of the first minutes of the hour.
	var list []map[string]any
	for m := 0; m < appliance.MaxSchedules; m++ {
		list = append(list, map[string]any{"id": fmt.Sprintf("s%d", m), "job": "backup_run", "every": "hourly", "minute": m, "enabled": true})
	}
	status["applied_schedules"] = list
	fake := &fakeAppliance{status: status}
	// The clock moves 15 seconds each time the agent reads it.
	clock := &fakeClock{t: time.Date(2026, 10, 2, 9, 59, 30, 0, time.UTC)}
	now := func() time.Time { clock.Add(15 * time.Second); return clock.Now() }
	a := e.agent(func(o *Options) { o.Appliance = fake; o.Now = now; o.Location = time.UTC })
	stop := start(t, a)
	waitFor(t, "a scheduled job while the API is down", func() bool { return len(fake.calls(ActionApplianceRunJob)) > 0 })
	stop()
	if d := e.device(); len(d.Samples) != 0 {
		t.Fatal("the outage did not hold")
	}
	raw, _ := json.Marshal(a.sched.report())
	if !strings.Contains(string(raw), `"last_status":"ok"`) {
		t.Fatalf("report: %s", raw)
	}
}
