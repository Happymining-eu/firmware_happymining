package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/helper"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/seal"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/testapi"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/version"
)

// fakeAppliance is a fake root helper for the appliance actions.
type fakeAppliance struct {
	mu       sync.Mutex
	requests []helper.Request
	// status is the result of appliance-status (nil: statusErr or statusResp).
	status     map[string]any
	statusErr  error
	statusResp *helper.Response
	// block makes appliance-status wait until its context ends.
	block bool
	// Responses of the other actions (zero value: OK).
	apply, runJob, install       *helper.Response
	applyErr, runJobErr, instErr error
}

func (f *fakeAppliance) Do(ctx context.Context, req helper.Request) (helper.Response, error) {
	f.mu.Lock()
	f.requests = append(f.requests, req)
	block := f.block
	f.mu.Unlock()
	f.mu.Lock()
	defer f.mu.Unlock()
	pick := func(r *helper.Response, err error, detail string) (helper.Response, error) {
		if err != nil {
			return helper.Response{}, err
		}
		if r != nil {
			return *r, nil
		}
		return helper.Response{OK: true, Detail: detail}, nil
	}
	switch req.Action {
	case ActionApplianceStatus:
		if block {
			f.mu.Unlock()
			<-ctx.Done()
			f.mu.Lock()
			return helper.Response{}, ctx.Err()
		}
		if f.statusErr != nil {
			return helper.Response{}, f.statusErr
		}
		if f.statusResp != nil {
			return *f.statusResp, nil
		}
		raw, _ := json.Marshal(f.status)
		return helper.Response{OK: true, Result: raw}, nil
	case ActionApplianceApply:
		return pick(f.apply, f.applyErr, "pending")
	case ActionApplianceRunJob:
		return pick(f.runJob, f.runJobErr, "started")
	case ActionUpdateInstall:
		return pick(f.install, f.instErr, "install started")
	}
	return helper.Response{Code: CodeInvalid, Detail: "unknown action"}, nil
}

func (f *fakeAppliance) calls(action string) []helper.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []helper.Request
	for _, r := range f.requests {
		if r.Action == action {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeAppliance) set(mod func(f *fakeAppliance)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mod(f)
}

func mustKey(t *testing.T) string {
	t.Helper()
	k, err := seal.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k.Public()
}

// cloudStatus is a helper status as the contract describes it.
func cloudStatus(t *testing.T) map[string]any {
	return map[string]any{
		"schema": 1, "control": "cloud", "applied_revision": 0, "apply_status": "applied", "apply_detail": "",
		"mode": "vast", "seal_public_key": mustKey(t),
		"capabilities": map[string]bool{"plugins": true, "nas": true, "backup": true, "update": true, "docker": true},
		"catalog":      []map[string]string{{"id": "ollama", "version": "1"}},
		"plugins":      []map[string]any{{"id": "ollama", "state": "stopped", "detail": "", "version": "1", "ports": []int{11434}}},
		"nas":          []map[string]any{},
		"secrets":      []map[string]any{},
		"vectorizer":   map[string]any{"state": "disabled", "last_run_at": "", "last_ok_at": "", "files_indexed": 0, "files_failed": 0, "files_skipped": 0, "chunks": 0, "detail": ""},
		"backup":       map[string]any{"state": "disabled", "key_present": false, "key_id": "", "last_ok_at": "", "last_size_bytes": 0, "detail": ""},
		"update":       map[string]any{"current_version": version.Version, "state": "idle", "target_version": "", "detail": ""},
		"applied_schedules": []map[string]any{
			{"id": "nightly-sync", "job": "vectorize_sync", "every": "daily", "hour": 2, "minute": 30, "enabled": true},
		},
	}
}

func TestApplianceObjectIsSentRedactedAndSanitised(t *testing.T) {
	e := newEnv(t)
	fake := &fakeAppliance{status: cloudStatus(t)}
	long := strings.Repeat("é", 800)
	fake.status["plugins"] = []map[string]any{
		{"id": "ollama", "state": "running", "detail": "token " + e.cred.Token + " " + long, "version": "1", "ports": []int{11434, 70000}},
		{"id": "Bad Id", "state": "running"},
	}
	fake.status["applied_schedules"] = []map[string]any{
		{"id": "nightly-sync", "job": "vectorize_sync", "every": "daily", "hour": 2, "minute": 30, "enabled": true},
		{"id": "bad", "job": "shell", "every": "daily", "hour": 2, "minute": 30, "enabled": true},
		{"id": "bad2", "job": "backup_run", "every": "hourly", "hour": 2, "minute": 30, "enabled": true},
	}
	a := e.agent(func(o *Options) { o.StopAfterSamples = 2; o.Appliance = fake })
	runFor(t, a)

	d := e.device()
	if len(d.ApplianceReports) == 0 {
		t.Fatal("no appliance object was sent")
	}
	raw := d.ApplianceReports[len(d.ApplianceReports)-1]
	if bytes.Contains(raw, []byte(e.cred.Token)) || bytes.Contains(raw, []byte("applied_schedules")) {
		t.Fatalf("the appliance object leaks the credential or the helper's schedule list: %s", raw)
	}
	rep, ok := d.LastAppliance()
	if !ok {
		t.Fatal("undecodable appliance object")
	}
	if len(rep.Plugins) != 1 || len([]rune(rep.Plugins[0].Detail)) > appliance.MaxReportedDetail ||
		len(rep.Plugins[0].Ports) != 1 || rep.Plugins[0].State != "running" {
		t.Fatalf("plugins not sanitised: %+v", rep.Plugins)
	}
	if !strings.Contains(rep.Plugins[0].Detail, "[REDACTED") {
		t.Fatalf("detail not redacted: %q", rep.Plugins[0].Detail[:60])
	}
	if len(rep.Schedules) != 1 || rep.Schedules[0].ID != "nightly-sync" || rep.Schedules[0].LastStatus != "never" ||
		rep.Schedules[0].NextRunAt == "" {
		t.Fatalf("schedules: %+v", rep.Schedules)
	}
	if rep.Control != "cloud" || !rep.Capabilities.Update || rep.Update.CurrentVersion != version.Version {
		t.Fatalf("report: %+v", rep)
	}
	if !strings.Contains(e.logs.String(), "a schedule of the applied document is ignored") {
		t.Error("an invalid schedule should be logged")
	}
	if st, err := ReadState(e.stateDir); err != nil || st.MachineID != e.cred.MachineID {
		t.Fatalf("the state file must carry the machine id: %+v %v", st, err)
	}
}

func TestHelperUnavailableSendsMinimalObjectAndTelemetryFlows(t *testing.T) {
	e := newEnv(t)
	// The real client against a socket that does not exist.
	missing := &helper.Client{SocketPath: filepath.Join(t.TempDir(), "absent.sock"), Timeout: time.Second}
	a := e.agent(func(o *Options) { o.StopAfterSamples = 3; o.Appliance = missing })
	runFor(t, a)
	d := e.device()
	wantContiguous(t, d, 1, 3)
	rep, ok := d.LastAppliance()
	if !ok {
		t.Fatal("no appliance object")
	}
	if rep.Capabilities != (appliance.Capabilities{}) || rep.ApplyStatus != appliance.ApplyDisabled ||
		!strings.Contains(rep.ApplyDetail, "not reachable") || rep.Control != appliance.StateUnknown {
		t.Fatalf("minimal object expected: %+v", rep)
	}
	if rep.Update.CurrentVersion != version.Version {
		t.Fatalf("update state: %+v", rep.Update)
	}
}

func TestHelperRefusalSendsMinimalObject(t *testing.T) {
	e := newEnv(t)
	fake := &fakeAppliance{statusResp: &helper.Response{Code: CodeInvalid, Detail: "unknown action"}}
	a := e.agent(func(o *Options) { o.StopAfterSamples = 1; o.Appliance = fake })
	runFor(t, a)
	rep, _ := e.device().LastAppliance()
	if rep.ApplyStatus != appliance.ApplyDisabled || !strings.Contains(rep.ApplyDetail, "refused appliance-status (invalid): unknown action") {
		t.Fatalf("report: %+v", rep)
	}
}

func TestSlowHelperDoesNotHoldUpTelemetry(t *testing.T) {
	e := newEnv(t)
	fake := &fakeAppliance{block: true}
	a := e.agent(func(o *Options) {
		o.StopAfterSamples = 3
		o.Appliance = fake
		o.ApplianceStatusTimeout = 30 * time.Millisecond
	})
	started := time.Now()
	runFor(t, a)
	if time.Since(started) > 10*time.Second {
		t.Fatalf("the run took %v", time.Since(started))
	}
	d := e.device()
	wantContiguous(t, d, 1, 3)
	rep, _ := d.LastAppliance()
	if rep.ApplyStatus != appliance.ApplyDisabled || !strings.Contains(rep.ApplyDetail, "deadline exceeded") {
		t.Fatalf("report: %+v", rep)
	}
}

func TestWithoutApplianceHelperNothingAboutTheApplianceIsExchanged(t *testing.T) {
	e := newEnv(t)
	e.api.SetApplianceDocument(e.cred.DeviceID, json.RawMessage(`{"schema":1,"revision":2,"mode":"vast"}`))
	a := e.agent(func(o *Options) { o.StopAfterSamples = 3 })
	runFor(t, a)
	d := e.device()
	wantContiguous(t, d, 1, 3)
	if len(d.ApplianceReports) != 0 || len(d.DocumentsSent) != 0 {
		t.Fatalf("an agent without appliance helper must exchange nothing about it: %d reports, %v documents",
			len(d.ApplianceReports), d.DocumentsSent)
	}
}

const testDocument = `{"schema": 1, "revision": 3, "mode": "private_ai",
  "plugins": [{"id": "ollama", "enabled": true, "settings": {}}], "secrets": {}}`

func compact(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(s)); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestDocumentIsHandedToTheHelperOncePerRevision(t *testing.T) {
	e := newEnv(t)
	if !e.api.SetApplianceDocument(e.cred.DeviceID, json.RawMessage(testDocument)) {
		t.Fatal("document not stored")
	}
	// The helper keeps reporting revision 0 (the apply is still pending), so
	// the server sends the document with every heartbeat.
	fake := &fakeAppliance{status: cloudStatus(t)}
	a := e.agent(func(o *Options) { o.StopAfterSamples = 6; o.Appliance = fake })
	runFor(t, a)
	d := e.device()
	if len(d.DocumentsSent) < 2 {
		t.Fatalf("the test needs the document sent several times: %v", d.DocumentsSent)
	}
	applies := fake.calls(ActionApplianceApply)
	if len(applies) != 1 {
		t.Fatalf("the same revision was handed to the helper %d times", len(applies))
	}
	if !bytes.Equal(applies[0].Document, compact(t, testDocument)) {
		t.Fatalf("handed document differs: %s", applies[0].Document)
	}

	// A new revision is handed over too.
	next := strings.Replace(testDocument, `"revision": 3`, `"revision": 4`, 1)
	e.api.SetApplianceDocument(e.cred.DeviceID, json.RawMessage(next))
	b := e.agent(func(o *Options) { o.StopAfterSamples = 2; o.Appliance = fake })
	runFor(t, b)
	if got := fake.calls(ActionApplianceApply); len(got) != 2 || !bytes.Contains(got[1].Document, []byte(`"revision":4`)) {
		t.Fatalf("revision 4 not handed over: %d", len(got))
	}
}

func TestDocumentStopsOnceTheHelperReportsItApplied(t *testing.T) {
	e := newEnv(t)
	e.api.SetApplianceDocument(e.cred.DeviceID, json.RawMessage(testDocument))
	fake := &fakeAppliance{status: cloudStatus(t)}
	fake.status["applied_revision"] = 3
	a := e.agent(func(o *Options) { o.StopAfterSamples = 3; o.Appliance = fake })
	runFor(t, a)
	if d := e.device(); len(d.DocumentsSent) != 0 || len(fake.calls(ActionApplianceApply)) != 0 {
		t.Fatalf("an applied revision must not travel again: %v", d.DocumentsSent)
	}
}

// unitAgent is an agent for tests of single steps, with a fake clock.
func unitAgent(t *testing.T, e *env, fake ApplianceHelper, clock *fakeClock) *Agent {
	t.Helper()
	a := e.agent(func(o *Options) {
		o.Appliance = fake
		if clock != nil {
			o.Now = clock.Now
		}
	})
	a.reloadCredential()
	return a
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestDocumentIsNotHandedWithoutCloudControl(t *testing.T) {
	e := newEnv(t)
	for _, control := range []string{"local", "unknown", ""} {
		fake := &fakeAppliance{status: cloudStatus(t)}
		fake.status["control"] = control
		a := unitAgent(t, e, fake, nil)
		a.refreshApplianceStatus(context.Background())
		a.onApplianceResponse(context.Background(), &protocol.ApplianceResponse{Revision: 3, Document: json.RawMessage(testDocument)})
		if n := len(fake.calls(ActionApplianceApply)); n != 0 {
			t.Fatalf("control %q: document handed over", control)
		}
	}
	// Helper not reachable: not handed over either.
	fake := &fakeAppliance{statusErr: helper.ErrUnavailable}
	a := unitAgent(t, e, fake, nil)
	a.refreshApplianceStatus(context.Background())
	a.onApplianceResponse(context.Background(), &protocol.ApplianceResponse{Revision: 3, Document: json.RawMessage(testDocument)})
	if n := len(fake.calls(ActionApplianceApply)); n != 0 {
		t.Fatal("document handed to a helper whose state is unknown")
	}
}

func TestOversizedOrInconsistentDocumentsAreRefused(t *testing.T) {
	e := newEnv(t)
	huge := `{"schema":1,"revision":5,"mode":"vast","pad":"` + strings.Repeat("x", appliance.MaxDocumentBytes) + `"}`
	cases := map[string]protocol.ApplianceResponse{
		"oversized":         {Revision: 5, Document: json.RawMessage(huge)},
		"revision mismatch": {Revision: 6, Document: json.RawMessage(strings.Replace(testDocument, "3", "7", 1))},
		"not an object":     {Revision: 8, Document: json.RawMessage(`[1,2,3]`)},
		"no revision":       {Revision: 9, Document: json.RawMessage(`{"schema":1}`)},
		"float revision":    {Revision: 10, Document: json.RawMessage(`{"revision":10.0}`)},
		"broken json":       {Revision: 11, Document: json.RawMessage(`{"revision":11`)},
	}
	for name, resp := range cases {
		fake := &fakeAppliance{status: cloudStatus(t)}
		a := unitAgent(t, e, fake, nil)
		a.refreshApplianceStatus(context.Background())
		a.onApplianceResponse(context.Background(), &resp)
		a.onApplianceResponse(context.Background(), &resp)
		if n := len(fake.calls(ActionApplianceApply)); n != 0 {
			t.Errorf("%s: handed to the helper", name)
		}
	}
	// Exactly at the limit is fine.
	pad := appliance.MaxDocumentBytes - len(`{"schema":1,"revision":12,"mode":"vast","pad":""}`)
	edge := `{"schema":1,"revision":12,"mode":"vast","pad":"` + strings.Repeat("x", pad) + `"}`
	fake := &fakeAppliance{status: cloudStatus(t)}
	a := unitAgent(t, e, fake, nil)
	a.refreshApplianceStatus(context.Background())
	a.onApplianceResponse(context.Background(), &protocol.ApplianceResponse{Revision: 12, Document: json.RawMessage(edge)})
	if n := len(fake.calls(ActionApplianceApply)); n != 1 {
		t.Fatalf("a 64 KiB document must be handed over: %d", n)
	}
}

func TestFailedHandOffIsRetriedWithBackoffAndInvalidIsNot(t *testing.T) {
	e := newEnv(t)
	clock := &fakeClock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	fake := &fakeAppliance{status: cloudStatus(t), applyErr: errors.New("helper not reachable")}
	a := unitAgent(t, e, fake, clock)
	a.refreshApplianceStatus(context.Background())
	resp := &protocol.ApplianceResponse{Revision: 3, Document: json.RawMessage(testDocument)}
	a.onApplianceResponse(context.Background(), resp)
	a.onApplianceResponse(context.Background(), resp) // too early: not again
	if n := len(fake.calls(ActionApplianceApply)); n != 1 {
		t.Fatalf("calls %d", n)
	}
	clock.Add(applyRetryMin + time.Second)
	fake.set(func(f *fakeAppliance) {
		f.applyErr = nil
		f.apply = &helper.Response{Code: CodeBusy, Detail: "apply running"}
	})
	a.onApplianceResponse(context.Background(), resp)
	if n := len(fake.calls(ActionApplianceApply)); n != 2 {
		t.Fatalf("not retried after the delay: %d", n)
	}
	// The delay doubled: one minute later is still too early.
	clock.Add(applyRetryMin + time.Second)
	a.onApplianceResponse(context.Background(), resp)
	if n := len(fake.calls(ActionApplianceApply)); n != 2 {
		t.Fatalf("retried too early: %d", n)
	}
	clock.Add(applyRetryMin)
	fake.set(func(f *fakeAppliance) {
		f.apply = &helper.Response{Code: CodeInvalid, Detail: "plugins.0.id: not in the catalog"}
	})
	a.onApplianceResponse(context.Background(), resp)
	clock.Add(time.Hour)
	a.onApplianceResponse(context.Background(), resp)
	if n := len(fake.calls(ActionApplianceApply)); n != 3 {
		t.Fatalf("a document the helper refused as invalid must not be offered again: %d", n)
	}
}

// The agent's report types are exactly what the fake API accepts.
func TestMinimalReportPassesTheFakeAPIValidation(t *testing.T) {
	e := newEnv(t)
	a := unitAgent(t, e, &fakeAppliance{statusErr: helper.ErrUnavailable}, nil)
	raw := a.applianceReport(context.Background())
	if _, err := testapi.ValidateAppliance(raw); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
}
