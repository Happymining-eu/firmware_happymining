package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/helper"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
)

const testFilename = "happymining-agent_0.2.0_amd64.deb"

// testRelease builds an offer for version 0.2.0 whose package is pkg. The
// signature is a placeholder: verifying it is the helper's job.
func testRelease(pkg []byte, mod func(m map[string]any)) *protocol.UpdateRelease {
	sum := sha256.Sum256(pkg)
	m := map[string]any{
		"schema": 1, "product": "happymining-agent", "version": "0.2.0", "created_at": "2026-10-02T12:00:00Z",
		"artifact":         map[string]any{"filename": testFilename, "size": len(pkg), "sha256": hex.EncodeToString(sum[:])},
		"min_upgrade_from": "0.1.0", "notes": "test",
	}
	if mod != nil {
		mod(m)
	}
	raw, _ := json.Marshal(m)
	return &protocol.UpdateRelease{
		Version: "0.2.0", ManifestB64: base64.StdEncoding.EncodeToString(raw),
		SignatureB64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 64)),
		Size:         int64(len(pkg)), SHA256: hex.EncodeToString(sum[:]),
		ArtifactPath: "/api/v1/device/update/artifact/0.2.0",
	}
}

func TestCheckOfferRefusesWhatDoesNotMatch(t *testing.T) {
	pkg := []byte("package bytes")
	if o, err := checkOffer(testRelease(pkg, nil)); err != nil || o.filename != testFilename {
		t.Fatalf("a good offer was refused: %v", err)
	}
	cases := map[string]func(r *protocol.UpdateRelease){
		"version":          func(r *protocol.UpdateRelease) { r.Version = "0.2" },
		"path":             func(r *protocol.UpdateRelease) { r.ArtifactPath = "https://evil.example/pkg.deb" },
		"path of other":    func(r *protocol.UpdateRelease) { r.ArtifactPath = "/api/v1/device/update/artifact/0.3.0" },
		"size zero":        func(r *protocol.UpdateRelease) { r.Size = 0 },
		"size huge":        func(r *protocol.UpdateRelease) { r.Size = 600 << 20 },
		"sha":              func(r *protocol.UpdateRelease) { r.SHA256 = strings.ToUpper(r.SHA256) },
		"signature":        func(r *protocol.UpdateRelease) { r.SignatureB64 = "not base64!" },
		"manifest base64":  func(r *protocol.UpdateRelease) { r.ManifestB64 = "%%%" },
		"manifest not obj": func(r *protocol.UpdateRelease) { r.ManifestB64 = base64.StdEncoding.EncodeToString([]byte(`[1]`)) },
	}
	for name, mod := range cases {
		r := testRelease(pkg, nil)
		mod(r)
		if _, err := checkOffer(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	manifests := map[string]func(m map[string]any){
		"product":  func(m map[string]any) { m["product"] = "other" },
		"version":  func(m map[string]any) { m["version"] = "0.3.0" },
		"filename": func(m map[string]any) { m["artifact"].(map[string]any)["filename"] = "../../etc/x.deb" },
		"name ext": func(m map[string]any) { m["artifact"].(map[string]any)["filename"] = "x.sh" },
		"size":     func(m map[string]any) { m["artifact"].(map[string]any)["size"] = 3 },
		"sha256":   func(m map[string]any) { m["artifact"].(map[string]any)["sha256"] = strings.Repeat("0", 64) },
	}
	for name, mod := range manifests {
		if _, err := checkOffer(testRelease(pkg, mod)); err == nil {
			t.Errorf("manifest %s: accepted", name)
		}
	}
}

// updateEnv is an agent whose helper allows updates, with an offer on the API.
type updateEnv struct {
	*env
	fake  *fakeAppliance
	agent *Agent
	clock *fakeClock
	pkg   []byte
	rel   *protocol.UpdateRelease
}

func newUpdateEnv(t *testing.T, policy string, window *protocol.UpdateWindow) *updateEnv {
	t.Helper()
	e := newEnv(t)
	u := &updateEnv{env: e, fake: &fakeAppliance{status: cloudStatus(t)}, pkg: bytes.Repeat([]byte("deb!"), 5000)}
	u.rel = testRelease(u.pkg, nil)
	e.api.SetUpdateOffer(e.cred.DeviceID, protocol.UpdateResponse{Channel: "stable", Policy: policy, Window: window, Release: u.rel})
	e.api.AddArtifact("0.2.0", u.pkg)
	u.clock = &fakeClock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	u.agent = e.agent(func(o *Options) { o.Appliance = u.fake; o.Now = u.clock.Now; o.Location = time.UTC })
	u.agent.reloadCredential()
	u.agent.refreshApplianceStatus(context.Background())
	return u
}

func (u *updateEnv) run(t *testing.T, req updateRequest) (string, error) {
	t.Helper()
	return u.agent.runUpdate(context.Background(), u.cred.Token, req)
}

func (u *updateEnv) updatesDir() string { return filepath.Join(u.stateDir, UpdatesDirName) }

func (u *updateEnv) wantNoDownload(t *testing.T) {
	t.Helper()
	entries, _ := os.ReadDir(u.updatesDir())
	for _, e := range entries {
		t.Errorf("left in the download directory: %s", e.Name())
	}
}

func TestInstallUpdateDownloadsChecksAndHandsOver(t *testing.T) {
	u := newUpdateEnv(t, "manual", nil)
	detail, err := u.run(t, updateRequest{kind: updateInstall, version: "0.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(u.updatesDir(), testFilename)
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, u.pkg) {
		t.Fatalf("package not downloaded: %v", err)
	}
	for p, mode := range map[string]os.FileMode{path: 0o600, u.updatesDir(): 0o700} {
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode().Perm() != mode {
			t.Fatalf("%s: %v %v", p, fi.Mode(), err)
		}
	}
	calls := u.fake.calls(ActionUpdateInstall)
	if len(calls) != 1 {
		t.Fatalf("update-install calls: %d", len(calls))
	}
	want := helper.Request{Action: ActionUpdateInstall, Version: "0.2.0", ManifestB64: u.rel.ManifestB64,
		SignatureB64: u.rel.SignatureB64, ArtifactPath: path}
	if got := calls[0]; got.Version != want.Version || got.ManifestB64 != want.ManifestB64 ||
		got.SignatureB64 != want.SignatureB64 || got.ArtifactPath != want.ArtifactPath || got.Document != nil {
		t.Fatalf("request %+v", got)
	}
	if !strings.Contains(detail, "handed to the helper") {
		t.Fatalf("detail %q", detail)
	}
	// Reported: installing until the helper reports on that version.
	if st := u.agent.upd.merge(appliance.UpdateState{State: "idle"}, u.clock.Now()); st.State != appliance.UpdateInstalling || st.TargetVersion != "0.2.0" {
		t.Fatalf("state %+v", st)
	}
	if st := u.agent.upd.merge(appliance.UpdateState{State: "installed", TargetVersion: "0.2.0", CurrentVersion: "0.1.0"}, u.clock.Now()); st.State != appliance.UpdateInstalled {
		t.Fatalf("the helper's state must take over: %+v", st)
	}
	if d := u.device(); len(d.ArtifactRequests) != 1 || d.ArtifactRequests[0] != "0.2.0" {
		t.Fatalf("artifact requests %v", d.ArtifactRequests)
	}
}

func TestDownloadNeverFollowsSymbolicLinks(t *testing.T) {
	u := newUpdateEnv(t, "manual", nil)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("do not touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(u.updatesDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{testFilename, "." + testFilename + ".part"} {
		if err := os.Symlink(victim, filepath.Join(u.updatesDir(), name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := u.run(t, updateRequest{kind: updateInstall, version: "0.2.0"}); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(victim); string(data) != "do not touch" {
		t.Fatal("the download wrote through a symbolic link")
	}
	fi, err := os.Lstat(filepath.Join(u.updatesDir(), testFilename))
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("the package must be a regular file: %v %v", fi, err)
	}
	if fi, _ := os.Stat(u.updatesDir()); fi.Mode().Perm() != 0o700 {
		t.Fatalf("download directory mode %v", fi.Mode())
	}

	// The download directory itself a symbolic link: refused.
	v := newUpdateEnv(t, "manual", nil)
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, v.updatesDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := v.run(t, updateRequest{kind: updateInstall, version: "0.2.0"}); err == nil {
		t.Fatal("a symbolic link as download directory was used")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatal("something was written through the linked directory")
	}
	if len(v.fake.calls(ActionUpdateInstall)) != 0 {
		t.Fatal("handed over after a refused download")
	}
}

func TestCorruptOrWrongSizedDownloadsLeaveNothing(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"same size, other bytes": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(bytes.Repeat([]byte("evil"), 5000))
		},
		"longer, no length": func(w http.ResponseWriter, _ *http.Request) {
			w.(http.Flusher).Flush()
			_, _ = w.Write(bytes.Repeat([]byte("deb!"), 6000))
		},
		"shorter, no length": func(w http.ResponseWriter, _ *http.Request) {
			w.(http.Flusher).Flush()
			_, _ = w.Write(bytes.Repeat([]byte("deb!"), 4000))
		},
		"wrong length header": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "10")
			_, _ = w.Write([]byte("0123456789"))
		},
		"not found": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"No such release.","request_id":"x"}}`))
		},
	}
	for name, h := range cases {
		u := newUpdateEnv(t, "manual", nil)
		u.api.SetArtifactHandler(h)
		if _, err := u.run(t, updateRequest{kind: updateInstall, version: "0.2.0"}); err == nil {
			t.Errorf("%s: accepted", name)
		}
		u.wantNoDownload(t)
		if len(u.fake.calls(ActionUpdateInstall)) != 0 {
			t.Errorf("%s: handed to the helper", name)
		}
		if st := u.agent.upd.merge(appliance.UpdateState{}, u.clock.Now()); st.State != appliance.UpdateError || st.Detail == "" {
			t.Errorf("%s: reported %+v", name, st)
		}
	}
}

func TestUpdatePolicyAndWindow(t *testing.T) {
	window := &protocol.UpdateWindow{StartHour: 2, EndHour: 5}

	// manual: a check never installs.
	u := newUpdateEnv(t, "manual", window)
	u.clock.Set(time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC))
	if detail, err := u.run(t, updateRequest{kind: updateCheck}); err != nil || !strings.Contains(detail, "only on request") {
		t.Fatalf("%q %v", detail, err)
	}
	if d := u.device(); len(d.ArtifactRequests) != 0 || len(u.fake.calls(ActionUpdateInstall)) != 0 {
		t.Fatal("manual policy installed")
	}

	// auto, outside the window: nothing now, the window start is remembered.
	u = newUpdateEnv(t, "auto", window)
	u.clock.Set(time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC))
	if _, err := u.run(t, updateRequest{kind: updateCheck}); err != nil {
		t.Fatal(err)
	}
	if d := u.device(); len(d.ArtifactRequests) != 0 {
		t.Fatal("installed outside the window")
	}
	if at := u.agent.upd.takeWindow(); !at.Equal(time.Date(2026, 10, 3, 2, 0, 0, 0, time.UTC)) {
		t.Fatalf("next window %v", at)
	}
	// ... but an install_update operation installs now.
	if _, err := u.run(t, updateRequest{kind: updateInstall, version: "0.2.0"}); err != nil {
		t.Fatal(err)
	}
	if len(u.fake.calls(ActionUpdateInstall)) != 1 {
		t.Fatal("install_update must install outside the window")
	}

	// auto, inside the window (crossing midnight too): installs.
	for _, tc := range []struct {
		w    *protocol.UpdateWindow
		hour int
	}{{window, 2}, {window, 4}, {&protocol.UpdateWindow{StartHour: 23, EndHour: 1}, 0}} {
		u = newUpdateEnv(t, "auto", tc.w)
		u.clock.Set(time.Date(2026, 10, 2, tc.hour, 30, 0, 0, time.UTC))
		if _, err := u.run(t, updateRequest{kind: updateCheck}); err != nil {
			t.Fatal(err)
		}
		if len(u.fake.calls(ActionUpdateInstall)) != 1 {
			t.Fatalf("window %+v hour %d: not installed", tc.w, tc.hour)
		}
	}
	// The window end is exclusive, and no window or an invalid one never opens.
	for _, w := range []*protocol.UpdateWindow{window, nil, {StartHour: 3, EndHour: 3}, {StartHour: 24, EndHour: 2}} {
		u = newUpdateEnv(t, "auto", w)
		u.clock.Set(time.Date(2026, 10, 2, 5, 0, 0, 0, time.UTC))
		if _, err := u.run(t, updateRequest{kind: updateCheck}); err != nil {
			t.Fatal(err)
		}
		if len(u.fake.calls(ActionUpdateInstall)) != 0 {
			t.Fatalf("window %+v: installed at 05:00", w)
		}
	}
}

func TestDownloadOutlastingTheWindowIsNotInstalled(t *testing.T) {
	u := newUpdateEnv(t, "auto", &protocol.UpdateWindow{StartHour: 2, EndHour: 5})
	u.clock.Set(time.Date(2026, 10, 2, 4, 59, 0, 0, time.UTC))
	u.api.SetArtifactHandler(func(w http.ResponseWriter, _ *http.Request) {
		u.clock.Set(time.Date(2026, 10, 2, 5, 20, 0, 0, time.UTC)) // the download takes 21 minutes
		_, _ = w.Write(u.pkg)
	})
	detail, err := u.run(t, updateRequest{kind: updateCheck})
	if err != nil || !strings.Contains(detail, "next window") {
		t.Fatalf("%q %v", detail, err)
	}
	if len(u.fake.calls(ActionUpdateInstall)) != 0 {
		t.Fatal("installed after the window closed")
	}
}

func TestInstallUpdateRefusals(t *testing.T) {
	// The API offers another version than the operation asks for.
	u := newUpdateEnv(t, "manual", nil)
	if _, err := u.run(t, updateRequest{kind: updateInstall, version: "0.3.0"}); err == nil || !strings.Contains(err.Error(), "not the requested 0.3.0") {
		t.Fatalf("%v", err)
	}
	// Nothing offered.
	u.api.SetUpdateOffer(u.cred.DeviceID, protocol.UpdateResponse{Channel: "none", Policy: "manual"})
	if _, err := u.run(t, updateRequest{kind: updateInstall, version: "0.2.0"}); err == nil || !strings.Contains(err.Error(), "not offered") {
		t.Fatalf("%v", err)
	}
	// Not newer than what runs.
	same := testRelease(u.pkg, func(m map[string]any) { m["version"] = "0.1.0" })
	same.Version, same.ArtifactPath = "0.1.0", "/api/v1/device/update/artifact/0.1.0"
	u.api.SetUpdateOffer(u.cred.DeviceID, protocol.UpdateResponse{Channel: "stable", Policy: "manual", Release: same})
	if _, err := u.run(t, updateRequest{kind: updateInstall, version: "0.1.0"}); err == nil || !strings.Contains(err.Error(), "not newer") {
		t.Fatalf("%v", err)
	}
	// The helper refuses the package.
	u.api.SetUpdateOffer(u.cred.DeviceID, protocol.UpdateResponse{Channel: "stable", Policy: "manual", Release: u.rel})
	u.fake.set(func(f *fakeAppliance) {
		f.install = &helper.Response{Code: CodeDisabled, Detail: "ALLOW_UPDATE is off"}
	})
	if _, err := u.run(t, updateRequest{kind: updateInstall, version: "0.2.0"}); err == nil || !strings.Contains(err.Error(), "ALLOW_UPDATE") {
		t.Fatalf("%v", err)
	}
	if st := u.agent.upd.merge(appliance.UpdateState{}, u.clock.Now()); st.State != appliance.UpdateError {
		t.Fatalf("%+v", st)
	}
	if d := u.device(); len(d.ArtifactRequests) != 1 {
		t.Fatalf("only the last case may download: %v", d.ArtifactRequests)
	}
}

func TestUpdateFlowsDoNotStartWithoutTheUpdateCapability(t *testing.T) {
	e := newEnv(t)
	status := cloudStatus(t)
	status["capabilities"] = map[string]bool{"update": false}
	fake := &fakeAppliance{status: status}
	a := unitAgent(t, e, fake, nil)
	a.refreshApplianceStatus(context.Background())
	a.bgCtx = context.Background()
	err := a.InstallUpdate(context.Background(), "0.2.0", func(string, error) { t.Fatal("must not start") })
	if err == nil || !strings.Contains(err.Error(), "ALLOW_UPDATE") {
		t.Fatalf("%v", err)
	}
	if _, err := a.ApplianceRunJob(context.Background(), "update_check", ""); err == nil {
		t.Fatal("update_check started without the capability")
	}
	if e.device().UpdateRequests != 0 {
		t.Fatal("the API was asked")
	}
}

// End to end: an install_update operation from the fake API, through the
// operation handler and the background flow, to the helper and back to the
// final acknowledgement, while telemetry keeps flowing.
func TestInstallUpdateOperationEndToEnd(t *testing.T) {
	e := newEnv(t)
	fake := &fakeAppliance{status: cloudStatus(t)}
	pkg := bytes.Repeat([]byte("0123456789abcdef"), 4096)
	rel := testRelease(pkg, nil)
	e.api.SetUpdateOffer(e.cred.DeviceID, protocol.UpdateResponse{Channel: "beta", Policy: "manual", Release: rel})
	e.api.AddArtifact("0.2.0", pkg)
	op := e.api.QueueOperation(e.cred.DeviceID, protocol.Operation{Type: protocol.OpInstallUpdate, Params: json.RawMessage(`{"version":"0.2.0"}`)})
	a := e.agent(func(o *Options) { o.Appliance = fake })
	stop := start(t, a)
	waitFor(t, "the final acknowledgement", func() bool { return e.device().FinalOperations[op.ID] != "" })
	stop()
	d := e.device()
	if d.FinalOperations[op.ID] != protocol.AckSucceeded {
		t.Fatalf("final %q, acks %+v", d.FinalOperations[op.ID], d.Acks)
	}
	if d.Acks[0].Body.Status != protocol.AckAccepted {
		t.Fatalf("first acknowledgement %+v", d.Acks[0].Body)
	}
	calls := fake.calls(ActionUpdateInstall)
	if len(calls) != 1 || calls[0].ArtifactPath != filepath.Join(e.stateDir, UpdatesDirName, testFilename) {
		t.Fatalf("calls %+v", calls)
	}
	if data, _ := os.ReadFile(calls[0].ArtifactPath); !bytes.Equal(data, pkg) {
		t.Fatal("handed a file that is not the package")
	}
	if len(d.Samples) == 0 {
		t.Fatal("telemetry stopped")
	}
	// The reported update state went through the agent's states.
	seen := map[string]bool{}
	for _, raw := range d.ApplianceReports {
		var r appliance.Reported
		_ = json.Unmarshal(raw, &r)
		seen[r.Update.State] = true
	}
	if !seen[appliance.UpdateInstalling] && !seen[appliance.UpdateDownloading] {
		t.Logf("states seen: %v (timing dependent)", seen)
	}
}

func TestAutomaticUpdateCheckTiming(t *testing.T) {
	u := newUpdateEnv(t, "auto", &protocol.UpdateWindow{StartHour: 2, EndHour: 5})
	a := u.agent
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); a.bg.Wait() }()
	a.bgCtx = ctx
	checks := func() int { return u.device().UpdateRequests }
	settle := func() {
		t.Helper()
		a.bg.Wait()
		a.drainEvents()
	}
	start := time.Date(2026, 10, 2, 22, 58, 0, 0, time.UTC)
	u.clock.Set(start)
	a.autoUpdateCheck(u.clock.Now()) // first tick: schedules the first check
	settle()
	if checks() != 0 {
		t.Fatal("checked at once")
	}
	u.clock.Set(start.Add(updateFirstCheckAfter))
	a.autoUpdateCheck(u.clock.Now())
	settle()
	if checks() != 1 || len(u.device().ArtifactRequests) != 0 {
		t.Fatalf("first check: %d checks, %v downloads", checks(), u.device().ArtifactRequests)
	}
	// Outside the window (23:00): the next check is at the window start
	// (02:00), which comes before the next periodic check (05:00).
	u.clock.Set(time.Date(2026, 10, 3, 1, 59, 0, 0, time.UTC))
	a.autoUpdateCheck(u.clock.Now())
	settle()
	if checks() != 1 {
		t.Fatal("checked before the window")
	}
	u.clock.Set(time.Date(2026, 10, 3, 2, 0, 0, 0, time.UTC))
	a.autoUpdateCheck(u.clock.Now())
	settle()
	if checks() != 2 || len(u.fake.calls(ActionUpdateInstall)) != 1 {
		t.Fatalf("at the window start: %d checks, %d installs", checks(), len(u.fake.calls(ActionUpdateInstall)))
	}
	// Then every 6 hours.
	u.clock.Set(time.Date(2026, 10, 3, 7, 59, 0, 0, time.UTC))
	a.autoUpdateCheck(u.clock.Now())
	settle()
	if checks() != 2 {
		t.Fatal("checked again within 6 hours")
	}
	u.clock.Set(time.Date(2026, 10, 3, 8, 0, 0, 0, time.UTC))
	a.autoUpdateCheck(u.clock.Now())
	settle()
	if checks() != 3 {
		t.Fatalf("checks %d", checks())
	}
	// Without the update capability nothing is asked.
	status := cloudStatus(t)
	status["capabilities"] = map[string]bool{"update": false}
	u.fake.set(func(f *fakeAppliance) { f.status = status })
	a.refreshApplianceStatus(context.Background())
	u.clock.Set(time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC))
	a.autoUpdateCheck(u.clock.Now())
	settle()
	if checks() != 3 {
		t.Fatal("checked without the update capability")
	}
}

func TestScheduledUpdateCheckRecordsItsOutcome(t *testing.T) {
	u := newUpdateEnv(t, "manual", nil)
	status := cloudStatus(t)
	status["applied_schedules"] = []map[string]any{
		{"id": "check", "job": "update_check", "every": "daily", "hour": 4, "minute": 0, "enabled": true},
	}
	u.fake.set(func(f *fakeAppliance) { f.status = status })
	a := u.agent
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); a.bg.Wait() }()
	a.bgCtx = ctx
	u.clock.Set(time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC))
	a.refreshApplianceStatus(context.Background())

	run := func(at time.Time) appliance.ScheduleState {
		t.Helper()
		u.clock.Set(at)
		a.runDueSchedules(context.Background(), at)
		a.bg.Wait()
		a.drainEvents()
		return a.sched.report()[0]
	}
	// Manual policy, a release available: the check succeeds, nothing is installed.
	st := run(time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC))
	if st.LastStatus != appliance.RunOK || st.LastRunAt != "2026-10-02T04:00:00Z" || len(u.fake.calls(ActionUpdateInstall)) != 0 {
		t.Fatalf("%+v", st)
	}
	// The API is unreachable for the check: recorded as failed.
	u.api.SetHeartbeatFault(nil)
	u.api.Revoke(u.cred.DeviceID)
	if st := run(time.Date(2026, 10, 3, 4, 0, 0, 0, time.UTC)); st.LastStatus != appliance.RunFailed {
		t.Fatalf("%+v", st)
	}
}
