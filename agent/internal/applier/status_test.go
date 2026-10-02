package applier

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/backup"
)

func fullDoc(h *harness, rev int) map[string]any {
	doc := pluginsDoc(rev, plug("ollama", true, map[string]any{"models": []any{"bge-m3"}}), plug("qdrant", true, nil),
		plug("vectorizer", true, nil), plug("assistant", true, nil))
	doc["nas"] = []map[string]any{smbEntry("docs", "nas.lan", "documents", "", "indexer", "read"),
		nfsEntry("bk", "192.168.1.20", "/volume1/backup", "", "write")}
	doc["vectorizer"] = map[string]any{"sources": []any{"docs"}, "extensions": []any{"pdf"}, "exclude": []any{},
		"max_file_mib": 64, "embedding_model": "bge-m3", "ocr": false,
		"answer": map[string]any{"provider": "anthropic", "model": "claude-x", "secret": "ai.answer.api_key"}}
	doc["backup"] = map[string]any{"enabled": true, "destination": map[string]any{"kind": "nas", "nas_id": "bk", "subpath": "hm"},
		"include_models": false, "keep": 2}
	doc["schedules"] = []map[string]any{{"id": "nightly-sync", "job": "vectorize_sync", "every": "daily", "hour": 2, "minute": 30, "enabled": true}}
	doc["update"] = map[string]any{"channel": "stable", "policy": "manual"}
	doc["secrets"] = map[string]any{
		"nas.docs.password":        h.sealFor("nas.docs.password", "nas-secret-value"),
		"ai.answer.api_key":        h.sealFor("ai.answer.api_key", "sk-ant-secret-value"),
		"plugin.assistant.api_key": newHarness(h.t).sealFor("plugin.assistant.api_key", "x"), // for another machine
	}
	return doc
}

func TestStatusAfterApply(t *testing.T) {
	h := newHarness(t)
	h.env.Switches.AllowUnpinnedImages = true
	h.env.Switches.AllowForeignContainers = true
	h.sys.volumes["hm-vectorizer_state"] = true
	if out := h.apply(fullDoc(h, 7)); !out.OK {
		t.Fatalf("%+v", out)
	}
	vol := filepath.Join(h.env.Paths.DockerVolumes, "hm-vectorizer_state", "_data")
	h.writeFile(filepath.Join(vol, "status.json"), `{"state":"idle","last_run_at":"2026-10-02T02:30:00Z","last_ok_at":"2026-10-02T02:41:10Z",`+
		`"files_indexed":1820,"files_failed":3,"files_skipped":12,"chunks":40211,"detail":"ok"}`, 0o644)
	h.env.refreshPlugins(context.Background())
	h.sys.reset()
	res, err := Status(context.Background(), h.env)
	if err != nil {
		t.Fatal(err)
	}
	r := res.Reported
	if r.Schema != 1 || r.Control != "cloud" || r.AppliedRevision != 7 || r.Mode != "private_ai" ||
		!strings.HasPrefix(r.SealPublicKey, "hmk1.") || r.ApplyStatus != appliance.ApplyPartial {
		t.Fatalf("%+v", r)
	}
	if r.Capabilities != (appliance.Capabilities{Plugins: true, NAS: true, Backup: true, Update: true, Docker: true}) {
		t.Fatalf("%+v", r.Capabilities)
	}
	if len(r.Catalog) != 4 || r.Catalog[0].ID != "assistant" {
		t.Fatalf("%+v", r.Catalog)
	}
	states := map[string]string{}
	for _, p := range r.Plugins {
		states[p.ID] = p.State
	}
	// assistant: its optional secret was sealed for another machine.
	want := map[string]string{"ollama": "running", "qdrant": "running", "vectorizer": "running", "assistant": "error"}
	if !reflect.DeepEqual(states, want) {
		t.Fatalf("%+v", r.Plugins)
	}
	if !reflect.DeepEqual(r.NAS, []appliance.NASState{{ID: "docs", State: "mounted"}, {ID: "bk", State: "mounted"}}) {
		t.Fatalf("%+v", r.NAS)
	}
	secrets := map[string]string{}
	for _, s := range r.Secrets {
		secrets[s.Name] = s.State
	}
	if !reflect.DeepEqual(secrets, map[string]string{"ai.answer.api_key": "ok", "nas.docs.password": "ok", "plugin.assistant.api_key": "unreadable"}) {
		t.Fatalf("%+v", r.Secrets)
	}
	if r.Vectorizer.State != "idle" || r.Vectorizer.FilesIndexed != 1820 || r.Vectorizer.LastOKAt != "2026-10-02T02:41:10Z" {
		t.Fatalf("%+v", r.Vectorizer)
	}
	if r.Backup.State != appliance.BackupNoKey || r.Backup.KeyPresent {
		t.Fatalf("%+v", r.Backup)
	}
	if r.Update.CurrentVersion != "0.2.0" || r.Update.State != "idle" {
		t.Fatalf("%+v", r.Update)
	}
	if len(res.AppliedSchedules) != 1 || res.AppliedSchedules[0].ID != "nightly-sync" {
		t.Fatalf("%+v", res.AppliedSchedules)
	}
	// Fresh states, unchanged document: the status runs nothing.
	if len(h.sys.lines()) != 0 {
		t.Fatalf("%q", h.sys.lines())
	}
	// A backup key appears.
	key, _ := backup.NewKey()
	if err := backup.SaveKey(h.env.Paths.backupKeyPath(), key); err != nil {
		t.Fatal(err)
	}
	res, _ = Status(context.Background(), h.env)
	if res.Reported.Backup.State != appliance.BackupNever || !res.Reported.Backup.KeyPresent || res.Reported.Backup.KeyID != backup.KeyID(key) {
		t.Fatalf("%+v", res.Reported.Backup)
	}
	// Nothing secret anywhere in the result.
	raw, _ := json.Marshal(res)
	for _, s := range []string{"nas-secret-value", "sk-ant-secret-value", "hmseal1."} {
		if strings.Contains(string(raw), s) {
			t.Fatalf("%s in the status", s)
		}
	}
}

func TestStatusResultJSON(t *testing.T) {
	h := newHarness(t)
	h.mustApply(fullDoc(h, 1))
	res, err := Status(context.Background(), h.env)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, has := m["schedules"]; has {
		t.Fatal("the result has no schedules key")
	}
	for _, key := range []string{"schema", "control", "applied_revision", "apply_status", "apply_detail", "mode", "seal_public_key",
		"capabilities", "catalog", "plugins", "nas", "secrets", "vectorizer", "backup", "update", "applied_schedules"} {
		if _, has := m[key]; !has {
			t.Errorf("missing %s", key)
		}
	}
	if len(m) != 16 {
		t.Fatalf("%d keys: %s", len(m), raw)
	}
	var back StatusResult
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.AppliedSchedules, res.AppliedSchedules) || back.Reported.AppliedRevision != 1 ||
		len(back.Reported.Plugins) != len(res.Reported.Plugins) {
		t.Fatalf("%+v", back)
	}
	// The agent adds its schedule states to Reported and sends it.
	rep := back.Reported
	rep.Schedules = []appliance.ScheduleState{{ID: "nightly-sync", LastStatus: "never"}}
	rep.Sanitize()
	if _, err := json.Marshal(rep); err != nil {
		t.Fatal(err)
	}
}

func TestStatusSanitisesWhatItReads(t *testing.T) {
	h := newHarness(t)
	h.env.Switches.AllowUnpinnedImages = true
	h.sys.volumes["hm-vectorizer_state"] = true
	doc := fullDoc(h, 1)
	h.mustApply(doc)
	vol := filepath.Join(h.env.Paths.DockerVolumes, "hm-vectorizer_state", "_data")
	// A hostile status.json: unknown state, a huge detail with control
	// characters, negative counters.
	h.writeFile(filepath.Join(vol, "status.json"), `{"state":"pwned","detail":"`+strings.Repeat("x\\u001b", 2000)+`","files_indexed":-5}`, 0o644)
	h.env.refreshPlugins(context.Background())
	res, _ := Status(context.Background(), h.env)
	v := res.Reported.Vectorizer
	if v.State != "error" || len(v.Detail) > 500 || strings.ContainsRune(v.Detail, 0x1b) || v.FilesIndexed != 0 {
		t.Fatalf("%+v", v)
	}
	// A symbolic link in place of status.json is not followed.
	_ = os.Remove(filepath.Join(vol, "status.json"))
	secret := filepath.Join(h.root, "secret.json")
	h.writeFile(secret, `{"state":"idle","detail":"read through a link"}`, 0o600)
	if err := os.Symlink(secret, filepath.Join(vol, "status.json")); err != nil {
		t.Fatal(err)
	}
	h.env.refreshPlugins(context.Background())
	res, _ = Status(context.Background(), h.env)
	if strings.Contains(res.Reported.Vectorizer.Detail, "through a link") || res.Reported.Vectorizer.State != "error" {
		t.Fatalf("%+v", res.Reported.Vectorizer)
	}
	// A volume outside Docker's volume directory is refused.
	h.sys.override = func(argv []string) (fakeResp, bool) {
		if strings.HasPrefix(strings.Join(argv, " "), DockerPath+" volume inspect") {
			return fakeResp{stdout: "/etc\n"}, true
		}
		return fakeResp{}, false
	}
	h.env.refreshPlugins(context.Background())
	if st := h.state(); st.Vectorizer.State != "error" || !strings.Contains(st.Vectorizer.Detail, "cannot be found") {
		t.Fatalf("%+v", st.Vectorizer)
	}
}

func TestStatusTriggers(t *testing.T) {
	h := newHarness(t)
	h.mustApply(pluginsDoc(1, plug("qdrant", true, nil)))
	h.sys.reset()
	// Fresh: nothing.
	if _, err := Status(context.Background(), h.env); err != nil {
		t.Fatal(err)
	}
	if len(h.sys.lines()) != 0 {
		t.Fatalf("%q", h.sys.lines())
	}
	// Old plugin states: the refresh job is started, once per interval.
	h.now = h.now.Add(2 * time.Minute)
	Status(context.Background(), h.env)
	Status(context.Background(), h.env)
	if count(h.sys.lines(), SystemctlPath+" start --no-block "+JobUnit(JobStatusRefresh)) != 1 {
		t.Fatalf("%q", h.sys.lines())
	}
	// The switches change: an apply is asked for.
	h.sys.reset()
	h.env.Switches.AllowUnpinnedImages = true
	Status(context.Background(), h.env)
	if !h.sys.started(UnitApply) || h.state().ApplyStatus != appliance.ApplyPending {
		t.Fatalf("%q", h.sys.lines())
	}
	// Pending and recent: not asked again; pending for long: asked again.
	h.sys.reset()
	Status(context.Background(), h.env)
	if h.sys.started(UnitApply) {
		t.Fatal("asked twice")
	}
	h.now = h.now.Add(11 * time.Minute)
	Status(context.Background(), h.env)
	if !h.sys.started(UnitApply) {
		t.Fatal("a stale pending apply must be asked again")
	}
}

func TestStatusWithUnusableCatalog(t *testing.T) {
	h := newHarness(t)
	h.writeFile(filepath.Join(h.env.Paths.CatalogDir, "broken", "plugin.json"), "{", 0o644)
	h.writeFile(filepath.Join(h.env.Paths.CatalogDir, "broken", "compose.yaml"), "services: {}\n", 0o644)
	res, err := Status(context.Background(), h.env)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reported.ApplyStatus != appliance.ApplyRejected || !strings.Contains(res.Reported.ApplyDetail, "catalog") ||
		res.Reported.Control != "cloud" {
		t.Fatalf("%+v", res.Reported)
	}
	if out := QuickApply(context.Background(), h.env, mustJSON(t, pluginsDoc(1))); out.OK || out.Code != CodeFailed {
		t.Fatalf("%+v", out)
	}
	h.setProfile(map[string]any{"schema": 1, "control": "local"})
	if res, _ := Status(context.Background(), h.env); res.Reported.Control != "local" {
		t.Fatal("control from the profile even without a catalog")
	}
}

func TestShippedCatalogApplies(t *testing.T) {
	if _, err := appliance.LoadCatalog(shippedCatalog()); err != nil {
		t.Skipf("the shipped catalog does not load yet (being finished elsewhere): %v", err)
	}
	h := newHarnessWith(t, shippedCatalog())
	h.env.Switches.AllowForeignContainers = true
	doc := pluginsDoc(1, plug("ollama", true, map[string]any{"models": []any{"qwen3:8b"}}), plug("qdrant", true, nil),
		plug("open-webui", true, nil))
	doc["secrets"] = map[string]any{"plugin.open-webui.admin_password": h.sealFor("plugin.open-webui.admin_password", "pw")}
	if out := h.apply(doc); !out.OK {
		t.Fatalf("%+v", out)
	}
	st := h.state()
	for _, id := range []string{"ollama", "qdrant", "open-webui"} {
		if r, _ := st.findPlugin(id); r.ApplyState != appliance.PluginStarting {
			t.Fatalf("%s: %+v", id, r)
		}
	}
	env, _ := os.ReadFile(h.env.Paths.envFile("open-webui"))
	if !strings.Contains(string(env), `WEBUI_ADMIN_PASSWORD="pw"`) {
		t.Fatalf("%s", env)
	}
	if index(h.sys.lines(), DockerPath+" compose -p hm-ollama exec -T ollama ollama pull qwen3:8b") < 0 {
		t.Fatalf("%q", h.sys.lines())
	}
}
