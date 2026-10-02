package sim

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/agent"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/helper"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/seal"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/testapi"
)

const fixtures = "../../../appliance/testdata"

func fixtureCatalog(t *testing.T) *appliance.Catalog {
	t.Helper()
	c, err := appliance.LoadCatalog(filepath.Join(fixtures, "catalog"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func fixtureDocument(t *testing.T, name string) json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtures, "documents", "valid", name))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Document json.RawMessage `json:"document"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Document
}

var allCaps = appliance.Capabilities{Plugins: true, NAS: true, Backup: true, Update: true, Docker: true}

func TestSimulatorApplianceFlowEndToEnd(t *testing.T) {
	api := testapi.New()
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	stateDir := t.TempDir()
	opts := Options{
		APIURL: srv.URL, AllowInsecureLoopback: true, Machines: 1, PairingCodes: []string{api.NewPairingCode()},
		StateDir: stateDir, GPUModel: "rtx4090", GPUs: 1, Interval: 2 * time.Millisecond, Samples: 3, Seed: 3,
		BackoffBase: time.Millisecond, BackoffCap: 5 * time.Millisecond,
		Appliance: true, ApplianceCapabilities: allCaps, ApplianceCatalog: fixtureCatalog(t),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	summary, err := Run(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	m := summary.Machines[0]
	if seal.CheckPublicKey(m.SealPublicKey) != nil {
		t.Fatalf("no synthetic sealing key in the summary: %+v", m)
	}
	d, _ := api.Device(m.DeviceID)
	rep, ok := d.LastAppliance()
	if !ok || rep.Mode != appliance.ModeVast || rep.SealPublicKey != m.SealPublicKey || len(rep.Catalog) != 4 ||
		!rep.Capabilities.Plugins || rep.AppliedRevision != 0 {
		t.Fatalf("first report: %+v", rep)
	}

	// The cloud now has a document for the machine.
	if !api.SetApplianceDocument(m.DeviceID, fixtureDocument(t, "full.json")) {
		t.Fatal("document not stored")
	}
	opts.PairingCodes, opts.Samples = nil, 8
	summary, err = Run(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	m = summary.Machines[0]
	if m.ApplianceRevision != 12 {
		t.Fatalf("the document was not applied: %+v", m)
	}
	d, _ = api.Device(m.DeviceID)
	rep, _ = d.LastAppliance()
	if rep.AppliedRevision != 12 || rep.ApplyStatus != appliance.ApplyApplied || rep.Mode != appliance.ModePrivateAI {
		t.Fatalf("last report: %+v", rep)
	}
	running := map[string]string{}
	for _, p := range rep.Plugins {
		running[p.ID] = p.State
		if !strings.Contains(p.Detail, SyntheticDetail) {
			t.Errorf("plugin %s detail does not say synthetic: %q", p.ID, p.Detail)
		}
	}
	if running["ollama"] != appliance.PluginRunning || running["qdrant"] != appliance.PluginRunning {
		t.Fatalf("plugins: %+v", rep.Plugins)
	}
	if len(rep.Schedules) != 2 || rep.Schedules[0].NextRunAt == "" {
		t.Fatalf("schedules of the document are not reported: %+v", rep.Schedules)
	}
	// Sealed for another key: the machine reports it cannot open them.
	for _, s := range rep.Secrets {
		if s.State != appliance.SecretUnreadable {
			t.Fatalf("secrets: %+v", rep.Secrets)
		}
	}
	// A new run starts with an empty synthetic helper, which reports revision
	// 0: the document travels again and is applied again ("applying is
	// repeated at agent start").
	opts.Samples = 4
	if _, err := Run(ctx, opts); err != nil {
		t.Fatal(err)
	}
	d, _ = api.Device(m.DeviceID)
	if rep, _ := d.LastAppliance(); rep.AppliedRevision != 12 || rep.ApplyStatus != appliance.ApplyApplied {
		t.Fatalf("not applied again after a restart: %+v", rep)
	}
}

func TestSyntheticHelperValidatesDocuments(t *testing.T) {
	h, err := NewSyntheticHelper(allCaps, fixtureCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	bad := json.RawMessage(`{"schema":1,"revision":4,"mode":"private_ai","plugins":[{"id":"unknown","enabled":true}]}`)
	resp, _ := h.Do(ctx, helper.Request{Action: agent.ActionApplianceApply, Document: bad})
	if resp.OK || resp.Code != agent.CodeInvalid {
		t.Fatalf("an invalid document was accepted: %+v", resp)
	}
	status, _ := h.Do(ctx, helper.Request{Action: agent.ActionApplianceStatus})
	var st map[string]any
	_ = json.Unmarshal(status.Result, &st)
	if st["apply_status"] != "rejected" || st["applied_revision"] != float64(4) {
		t.Fatalf("status after a refused document: %v", st)
	}
	if _, has := st["schedules"]; has {
		t.Fatal("the helper's status must not carry schedules (only applied_schedules)")
	}
	if _, has := st["applied_schedules"]; !has {
		t.Fatal("applied_schedules missing")
	}
	// Every valid fixture is accepted.
	entries, _ := os.ReadDir(filepath.Join(fixtures, "documents", "valid"))
	for _, e := range entries {
		resp, _ := h.Do(ctx, helper.Request{Action: agent.ActionApplianceApply, Document: fixtureDocument(t, e.Name())})
		if !resp.OK {
			t.Errorf("%s: %+v", e.Name(), resp)
		}
	}
	// Jobs follow the capabilities; update-install is never faked.
	off, _ := NewSyntheticHelper(appliance.Capabilities{}, fixtureCatalog(t))
	if r, _ := off.Do(ctx, helper.Request{Action: agent.ActionApplianceRunJob, Job: "backup_run"}); r.OK || r.Code != agent.CodeDisabled {
		t.Fatalf("%+v", r)
	}
	if r, _ := off.Do(ctx, helper.Request{Action: agent.ActionApplianceApply, Document: fixtureDocument(t, "minimal.json")}); r.OK {
		t.Fatalf("applied with plugins and NAS off: %+v", r)
	}
	if r, _ := h.Do(ctx, helper.Request{Action: agent.ActionUpdateInstall, Version: "0.2.0"}); r.OK {
		t.Fatal("a simulated machine must never claim to install firmware")
	}
}

func TestSyntheticHelperOpensSecretsSealedForItsKey(t *testing.T) {
	h, err := NewSyntheticHelper(allCaps, fixtureCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(fixtureDocument(t, "full.json"), &doc)
	secrets := doc["secrets"].(map[string]any)
	for name := range secrets {
		sealed, err := seal.Seal(h.PublicKey(), name, []byte("synthetic value"))
		if err != nil {
			t.Fatal(err)
		}
		secrets[name] = sealed
	}
	raw, _ := json.Marshal(doc)
	if r, _ := h.Do(context.Background(), helper.Request{Action: agent.ActionApplianceApply, Document: raw}); !r.OK {
		t.Fatalf("%+v", r)
	}
	status, _ := h.Do(context.Background(), helper.Request{Action: agent.ActionApplianceStatus})
	var st appliance.Reported
	_ = json.Unmarshal(status.Result, &st)
	if len(st.Secrets) != len(secrets) {
		t.Fatalf("secrets %+v", st.Secrets)
	}
	for _, s := range st.Secrets {
		if s.State != appliance.SecretOK {
			t.Fatalf("secrets %+v", st.Secrets)
		}
	}
	if strings.Contains(string(status.Result), "synthetic value") {
		t.Fatal("a secret's value is in the status")
	}
}
