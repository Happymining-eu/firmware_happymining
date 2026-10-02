package agent

// Schedules (docs/appliance.md, section 4.6). The helper reports the schedules
// of the applied document; the agent runs them, in the machine's local time:
//
//   - a schedule's next run is computed with internal/schedule from the moment
//     the agent learns it (at start, or when it changes), so a run missed
//     while the machine or the agent was off is not caught up;
//   - a run that is due is started once; if the agent only gets to it more
//     than missedGrace late (the machine was suspended, the clock jumped) it
//     is not started and the next one is computed;
//   - a job is never started twice at the same time: update_check runs in the
//     agent, one at a time; the other jobs are systemd units of the helper,
//     which systemd does not start again while they run (asking again then
//     succeeds without starting a second run);
//   - the outcome of the start is recorded: ok (the helper started the unit;
//     whether the job then did anything — it may find its feature not
//     configured — is in the helper's own record, not here), skipped (the
//     helper refused: switch off, or "busy" should a future helper say so),
//     failed.
//
// last_run_at and last_status survive a restart (schedules.json in the state
// directory); next_run_at is always computed again.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/helper"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
)

// SchedulesFileName holds the schedule history in the state directory.
const SchedulesFileName = "schedules.json"

// missedGrace is how late a due run may still be started.
const missedGrace = 15 * time.Minute

const maxSchedulesFileBytes = 64 * 1024

type scheduleEntry struct {
	s          appliance.Schedule
	key        string
	next       time.Time
	lastRun    time.Time
	lastStatus string
}

type scheduleHistory struct {
	LastRunAt  string `json:"last_run_at,omitempty"`
	LastStatus string `json:"last_status"`
}

type schedulesFile struct {
	Schedules map[string]scheduleHistory `json:"schedules"`
}

// scheduler holds the schedule list and its state. Only the agent loop uses it.
type scheduler struct {
	path    string
	loc     *time.Location
	entries []*scheduleEntry
	history map[string]scheduleHistory
	saveErr string
}

func newScheduler(stateDir string, loc *time.Location) (*scheduler, error) {
	s := &scheduler{path: filepath.Join(stateDir, SchedulesFileName), loc: loc, history: map[string]scheduleHistory{}}
	data, err := readBounded(s.path, maxSchedulesFileBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s, nil
	case err != nil:
		return s, err
	}
	var f schedulesFile
	if err := json.Unmarshal(data, &f); err != nil {
		return s, fmt.Errorf("%s is not valid; the schedule history starts again: %w", s.path, err)
	}
	for id, h := range f.Schedules {
		if reID.MatchString(id) && len(s.history) < 4*appliance.MaxSchedules {
			s.history[id] = h
		}
	}
	return s, nil
}

func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, fmt.Errorf("%s is not a regular file of at most %d bytes", path, max)
	}
	data := make([]byte, fi.Size())
	_, err = io.ReadFull(f, data)
	return data, err
}

func scheduleKey(s appliance.Schedule) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

// setSchedules replaces the schedule list. A schedule that did not change
// keeps its next run; a new or changed one gets its next run from now.
func (s *scheduler) setSchedules(list []appliance.Schedule, now time.Time) {
	old := map[string]*scheduleEntry{}
	for _, e := range s.entries {
		old[e.s.ID] = e
	}
	entries := make([]*scheduleEntry, 0, len(list))
	for _, item := range list {
		key := scheduleKey(item)
		if e, ok := old[item.ID]; ok && e.key == key {
			entries = append(entries, e)
			continue
		}
		e := &scheduleEntry{s: item, key: key, lastStatus: appliance.RunNever}
		if h, ok := s.history[item.ID]; ok {
			if t, err := time.Parse(time.RFC3339, h.LastRunAt); err == nil {
				e.lastRun = t
			}
			if h.LastStatus != "" {
				e.lastStatus = h.LastStatus
			}
		}
		if prev, ok := old[item.ID]; ok {
			e.lastRun, e.lastStatus = prev.lastRun, prev.lastStatus
		}
		if item.Enabled {
			e.next = item.Spec().Next(now.In(s.loc))
		}
		entries = append(entries, e)
	}
	s.entries = entries
}

// due returns the schedules whose run is due at now, and advances their next
// run. A run that is more than missedGrace late is dropped (returned in missed).
func (s *scheduler) due(now time.Time) (run, missed []appliance.Schedule) {
	for _, e := range s.entries {
		if !e.s.Enabled || e.next.IsZero() || now.Before(e.next) {
			continue
		}
		if now.Sub(e.next) > missedGrace {
			missed = append(missed, e.s)
		} else {
			run = append(run, e.s)
		}
		e.next = e.s.Spec().Next(now.In(s.loc))
	}
	return run, missed
}

// record stores the outcome of a run and persists the history. It returns an
// error only when the history could not be written (the run is still
// recorded in memory).
func (s *scheduler) record(id, status string, at time.Time) error {
	for _, e := range s.entries {
		if e.s.ID == id {
			e.lastRun, e.lastStatus = at, status
		}
	}
	s.history[id] = scheduleHistory{LastRunAt: appliance.FormatTime(at), LastStatus: status}
	for known := range s.history {
		if len(s.history) <= 4*appliance.MaxSchedules {
			break
		}
		if !s.has(known) {
			delete(s.history, known)
		}
	}
	data, err := json.MarshalIndent(schedulesFile{Schedules: s.history}, "", "  ")
	if err != nil {
		return err
	}
	return fsx.WriteFileAtomic(s.path, append(data, '\n'), 0o600, nil)
}

func (s *scheduler) has(id string) bool {
	for _, e := range s.entries {
		if e.s.ID == id {
			return true
		}
	}
	return false
}

// report returns the schedule part of the reported state.
func (s *scheduler) report() []appliance.ScheduleState {
	out := make([]appliance.ScheduleState, 0, len(s.entries))
	for _, e := range s.entries {
		st := appliance.ScheduleState{ID: e.s.ID, LastStatus: e.lastStatus, LastRunAt: appliance.FormatTime(e.lastRun)}
		if e.s.Enabled {
			st.NextRunAt = appliance.FormatTime(e.next)
		}
		out = append(out, st)
	}
	return out
}

// runDueSchedules starts every schedule that is due.
func (a *Agent) runDueSchedules(ctx context.Context, now time.Time) {
	run, missed := a.sched.due(now)
	for _, s := range missed {
		a.log.Warn("a scheduled run was missed (the agent was not running at that time); it is not caught up",
			"schedule", s.ID, "job", s.Job)
	}
	for _, s := range run {
		if ctx.Err() != nil {
			return
		}
		status, detail := a.startScheduled(ctx, s, now)
		if status == "" {
			continue // update_check: recorded when the check finishes
		}
		a.recordSchedule(s.ID, status, now)
		a.log.Info("scheduled job", "schedule", s.ID, "job", s.Job, "status", status,
			"detail", protocol.Truncate(a.o.Redactor.String(detail), 300))
	}
}

func (a *Agent) recordSchedule(id, status string, at time.Time) {
	if err := a.sched.record(id, status, at); err != nil {
		if msg := err.Error(); msg != a.sched.saveErr {
			a.sched.saveErr = msg
			a.log.Error("cannot store the schedule history", "error", msg)
		}
	}
}

// startScheduled starts one scheduled job and returns its status ("" when the
// status is recorded later).
func (a *Agent) startScheduled(ctx context.Context, s appliance.Schedule, now time.Time) (status, detail string) {
	if s.Job == appliance.JobUpdateCheck {
		id := s.ID
		err := a.startUpdate(updateRequest{kind: updateCheck, onDone: func(_ string, err error) {
			result := appliance.RunOK
			if err != nil {
				result = appliance.RunFailed
			}
			a.recordSchedule(id, result, now)
		}})
		var skip *skipError
		switch {
		case errors.As(err, &skip):
			return appliance.RunSkipped, skip.Error()
		case err != nil:
			return appliance.RunFailed, err.Error()
		}
		return "", "update check started"
	}
	resp, err := a.helperDo(ctx, applianceCallTimeout, helper.Request{Action: ActionApplianceRunJob, Job: s.Job, Plugin: s.Plugin})
	switch {
	case err != nil:
		return appliance.RunFailed, "the privileged helper is not reachable: " + err.Error()
	case resp.OK:
		return appliance.RunOK, resp.Detail
	case resp.Code == CodeDisabled || resp.Code == CodeBusy:
		// Not allowed or not configured on this machine, or still running.
		return appliance.RunSkipped, resp.Detail
	default:
		return appliance.RunFailed, fmt.Sprintf("the helper refused (%s): %s", protocol.Truncate(resp.Code, 40), resp.Detail)
	}
}
