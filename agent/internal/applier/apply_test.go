package applier

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/config"
)

func TestQuickApplyAcceptsEveryValidFixture(t *testing.T) {
	entries, err := os.ReadDir(fixtureDocs("valid"))
	if err != nil || len(entries) == 0 {
		t.Fatal(err)
	}
	for _, ent := range entries {
		t.Run(ent.Name(), func(t *testing.T) {
			h := newHarness(t)
			h.env.Switches.AllowUnpinnedImages = true
			doc := fixture(t, "valid", ent.Name())
			out := QuickApply(context.Background(), h.env, mustJSON(t, doc))
			if !out.OK {
				t.Fatalf("%+v", out)
			}
			res := out.Result.(ApplyResult)
			if res.ApplyStatus != appliance.ApplyPending {
				t.Fatalf("%+v", res)
			}
			if !h.sys.started(UnitApply) || len(h.sys.lines()) != 1 {
				t.Fatalf("the quick action only starts the unit: %q", h.sys.lines())
			}
			a, err := h.env.loadApplied()
			if err != nil || a == nil || a.Origin != OriginCloud || mode(t, h.env.Paths.appliedPath()) != 0o600 {
				t.Fatalf("%+v %v", a, err)
			}
			// apply-stored with secrets sealed for another key: it must
			// finish, and the state must be reportable.
			if err := ApplyStored(context.Background(), h.env); err != nil {
				t.Fatal(err)
			}
			st := h.state()
			if st.CloudRevision != int64(doc["revision"].(float64)) || st.ApplyStatus == appliance.ApplyPending ||
				st.ApplyStatus == appliance.ApplyRejected {
				t.Fatalf("%+v", st)
			}
			res2, err := Status(context.Background(), h.env)
			if err != nil {
				t.Fatal(err)
			}
			if res2.Reported.AppliedRevision != st.CloudRevision || res2.Reported.Control != "cloud" {
				t.Fatalf("%+v", res2.Reported)
			}
			assertFixedPrograms(t, h.sys)
		})
	}
}

func TestQuickApplyRefusesEveryInvalidFixture(t *testing.T) {
	entries, err := os.ReadDir(fixtureDocs("invalid"))
	if err != nil || len(entries) == 0 {
		t.Fatal(err)
	}
	for _, ent := range entries {
		t.Run(ent.Name(), func(t *testing.T) {
			h := newHarness(t)
			doc := fixture(t, "invalid", ent.Name())
			out := QuickApply(context.Background(), h.env, mustJSON(t, doc))
			if out.OK || out.Code != CodeInvalid {
				t.Fatalf("%+v", out)
			}
			if len(h.sys.lines()) != 0 {
				t.Fatalf("a refused document starts nothing: %q", h.sys.lines())
			}
			if _, err := os.Lstat(h.env.Paths.appliedPath()); err == nil {
				t.Fatal("a refused document is not stored")
			}
			if rev := revisionOf(mustJSON(t, doc)); rev > 0 {
				st := h.state()
				if st.CloudRevision != rev || st.ApplyStatus != appliance.ApplyRejected || st.ApplyDetail == "" {
					t.Fatalf("%+v", st)
				}
				if r, ok := out.Result.(ApplyResult); !ok || r.ApplyStatus != appliance.ApplyRejected || r.AppliedRevision != rev {
					t.Fatalf("%+v", out.Result)
				}
			}
		})
	}
}

func TestRejectedDocumentChangesNothing(t *testing.T) {
	h := newHarness(t)
	good := pluginsDoc(1, plug("qdrant", true, nil))
	h.mustApply(good)
	before, _ := os.ReadFile(h.env.Paths.appliedPath())
	bad := pluginsDoc(2, plug("qdrant", true, map[string]any{"nope": 1}))
	h.sys.reset()
	if out := h.apply(bad); out.OK || out.Code != CodeInvalid {
		t.Fatalf("%+v", out)
	}
	after, _ := os.ReadFile(h.env.Paths.appliedPath())
	if string(before) != string(after) || len(h.sys.lines()) != 0 {
		t.Fatal("a rejected document must change nothing")
	}
	st := h.state()
	if st.CloudRevision != 2 || st.ApplyStatus != appliance.ApplyRejected {
		t.Fatalf("%+v", st)
	}
	if r, _ := st.findPlugin("qdrant"); !r.Started {
		t.Fatal("the running plugin is left as it is")
	}
}

func TestLocalControl(t *testing.T) {
	h := newHarness(t)
	local := map[string]any{"schema": 1, "control": "local", "document": map[string]any{
		"schema": 1, "mode": "private_ai", "plugins": []any{plug("qdrant", true, nil)},
		"nas": []any{smbEntry("docs", "nas", "s", "", "u", "read")},
	}}
	h.setProfile(local)
	out := QuickApply(context.Background(), h.env, mustJSON(t, pluginsDoc(1, plug("ollama", true, nil))))
	if out.OK || out.Code != CodeLocallyControlled || len(h.sys.lines()) != 0 {
		t.Fatalf("%+v %q", out, h.sys.lines())
	}
	if _, err := os.Lstat(h.env.Paths.appliedPath()); err == nil {
		t.Fatal("a cloud document is not stored under local control")
	}
	// The status asks for the local document to be applied.
	res, err := Status(context.Background(), h.env)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reported.Control != "local" || res.Reported.AppliedRevision != 0 || !h.sys.started(UnitApply) {
		t.Fatalf("%+v %q", res.Reported, h.sys.lines())
	}
	// The secret is entered on the machine.
	if err := SecretSet(context.Background(), h.env, "nas.docs.password", strings.NewReader("local-pass\n")); err != nil {
		t.Fatal(err)
	}
	if err := ApplyStored(context.Background(), h.env); err != nil {
		t.Fatal(err)
	}
	st := h.state()
	if st.Origin != OriginLocal || st.ApplyStatus != appliance.ApplyApplied || st.CloudRevision != 0 {
		t.Fatalf("%+v", st)
	}
	cred, _ := os.ReadFile(h.env.Paths.credFile("docs"))
	if !strings.Contains(string(cred), "password=local-pass\n") {
		t.Fatalf("%q", cred)
	}
	if r, _ := st.findPlugin("qdrant"); !r.Started {
		t.Fatal("the local document's plugin must run")
	}
	// Nothing changed: the status does not ask again.
	h.sys.reset()
	if _, err := Status(context.Background(), h.env); err != nil {
		t.Fatal(err)
	}
	if h.sys.started(UnitApply) {
		t.Fatal("an unchanged local document must not be applied again")
	}
	// A secret name the profile does not refer to is refused.
	if err := SecretSet(context.Background(), h.env, "nas.other.password", strings.NewReader("x")); err == nil {
		t.Fatal("unknown secret name accepted")
	}
	for _, in := range []string{"", "\n", strings.Repeat("x", 4097)} {
		if err := SecretSet(context.Background(), h.env, "nas.docs.password", strings.NewReader(in)); err == nil {
			t.Fatalf("%d bytes accepted", len(in))
		}
	}
	raw, _ := os.ReadFile(h.env.Paths.localSecretsPath())
	if strings.Contains(string(raw), "local-pass") || mode(t, h.env.Paths.localSecretsPath()) != 0o600 {
		t.Fatal("local secrets must be sealed and root-only")
	}
}

func TestBrokenProfileRefusesEverything(t *testing.T) {
	h := newHarness(t)
	h.writeFile(h.env.Paths.ProfilePath, `{"schema":1,"control":"local","document":{"mode":"nope"}}`, 0o644)
	out := QuickApply(context.Background(), h.env, mustJSON(t, pluginsDoc(1)))
	if out.Code != CodeLocallyControlled {
		t.Fatalf("%+v", out)
	}
	res, err := Status(context.Background(), h.env)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reported.Control != "local" || res.Reported.ApplyStatus != appliance.ApplyRejected ||
		!strings.Contains(res.Reported.ApplyDetail, "local profile cannot be used") {
		t.Fatalf("%+v", res.Reported)
	}
	if err := ApplyStored(context.Background(), h.env); err != nil {
		t.Fatal(err)
	}
	if count(h.sys.lines(), DockerPath)+count(h.sys.lines(), MountPath) != 0 {
		t.Fatalf("nothing is applied: %q", h.sys.lines())
	}
	// A profile writable by others is refused as well.
	h.writeFile(h.env.Paths.ProfilePath, `{"schema":1,"control":"cloud"}`, 0o666)
	if out := QuickApply(context.Background(), h.env, mustJSON(t, pluginsDoc(1))); out.Code != CodeLocallyControlled {
		t.Fatalf("%+v", out)
	}
}

func TestStartupProfileUntilTheFirstCloudDocument(t *testing.T) {
	h := newHarness(t)
	h.setProfile(map[string]any{"schema": 1, "control": "cloud", "document": map[string]any{
		"schema": 1, "mode": "private_ai", "plugins": []any{plug("qdrant", true, nil)}}})
	if err := ApplyStored(context.Background(), h.env); err != nil {
		t.Fatal(err)
	}
	if st := h.state(); st.Origin != OriginLocal || !st.Plugins[0].Started {
		t.Fatalf("%+v", st)
	}
	h.sys.reset()
	h.mustApply(pluginsDoc(5, plug("ollama", true, nil)))
	st := h.state()
	if st.Origin != OriginCloud || st.CloudRevision != 5 {
		t.Fatalf("%+v", st)
	}
	if index(h.sys.lines(), DockerPath+" compose -p hm-qdrant down") < 0 {
		t.Fatalf("the start-up profile's plugin leaves: %q", h.sys.lines())
	}
}

func TestApplySwitchesOff(t *testing.T) {
	h := newHarness(t)
	h.env.Switches = config.Helper{}
	doc := pluginsDoc(3, plug("qdrant", true, nil))
	out := QuickApply(context.Background(), h.env, mustJSON(t, doc))
	if out.OK || out.Code != CodeDisabled || len(h.sys.lines()) != 0 {
		t.Fatalf("%+v %q", out, h.sys.lines())
	}
	if r := out.Result.(ApplyResult); r.AppliedRevision != 3 || r.ApplyStatus != appliance.ApplyDisabled {
		t.Fatalf("%+v", r)
	}
	res, _ := Status(context.Background(), h.env)
	if res.Reported.ApplyStatus != appliance.ApplyDisabled || len(h.sys.lines()) != 0 {
		t.Fatalf("%+v %q", res.Reported, h.sys.lines())
	}
	// The owner turns plugins on: the stored document is applied.
	h.env.Switches.AllowPlugins = true
	if _, err := Status(context.Background(), h.env); err != nil {
		t.Fatal(err)
	}
	if !h.sys.started(UnitApply) {
		t.Fatalf("%q", h.sys.lines())
	}
	if err := ApplyStored(context.Background(), h.env); err != nil {
		t.Fatal(err)
	}
	if r, _ := h.state().findPlugin("qdrant"); !r.Started {
		t.Fatal("not applied")
	}
}

func TestNewerDocumentDuringApplyIsAppliedToo(t *testing.T) {
	h := newHarness(t)
	sent := false
	h.sys.override = func(argv []string) (fakeResp, bool) {
		if !sent && strings.Join(argv, " ") == DockerPath+" network inspect hm-appliance" {
			sent = true
			out := QuickApply(context.Background(), h.env, mustJSON(h.t, pluginsDoc(2, plug("ollama", true, nil))))
			if !out.OK {
				h.t.Errorf("%+v", out)
			}
		}
		return fakeResp{}, false
	}
	h.env.Switches.AllowForeignContainers = true
	h.mustApply(pluginsDoc(1, plug("qdrant", true, nil)))
	st := h.state()
	if st.CloudRevision != 2 || st.PendingSHA256 != "" || st.ApplyStatus != appliance.ApplyApplied {
		t.Fatalf("%+v", st)
	}
	if r, _ := st.findPlugin("ollama"); !r.Started {
		t.Fatal("the newer document was not applied")
	}
	if _, ok := st.findPlugin("qdrant"); ok {
		t.Fatal("the older document's plugin left")
	}
}

func TestPendingDocumentIsNotStoredTwice(t *testing.T) {
	h := newHarness(t)
	doc := pluginsDoc(1, plug("qdrant", true, nil))
	QuickApply(context.Background(), h.env, mustJSON(t, doc))
	fi1, _ := os.Stat(h.env.Paths.appliedPath())
	out := QuickApply(context.Background(), h.env, mustJSON(t, doc))
	if !out.OK || out.Result.(ApplyResult).ApplyStatus != appliance.ApplyPending {
		t.Fatalf("%+v", out)
	}
	fi2, _ := os.Stat(h.env.Paths.appliedPath())
	if !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Fatal("the same pending document was written again")
	}
	// The unit is asked again (it may have died); systemd merges the start.
	if count(h.sys.lines(), SystemctlPath+" start --no-block "+UnitApply) != 2 {
		t.Fatalf("%q", h.sys.lines())
	}
}

func TestAppliedFileIsChecked(t *testing.T) {
	h := newHarness(t)
	if out := h.apply(pluginsDoc(1)); !out.OK {
		t.Fatalf("%+v", out)
	}
	raw, _ := os.ReadFile(h.env.Paths.appliedPath())
	if a, err := h.env.loadApplied(); err != nil || a == nil || a.Revision != 1 {
		t.Fatalf("%+v %v", a, err)
	}
	var a Applied
	_ = json.Unmarshal(raw, &a)
	a.Document = json.RawMessage(strings.Replace(string(a.Document), `"private_ai"`, `"vectorize"`, 1))
	data, _ := json.Marshal(a)
	h.writeFile(h.env.Paths.appliedPath(), string(data), 0o600)
	if _, err := h.env.loadApplied(); err == nil {
		t.Fatal("a changed applied.json must be refused")
	}
	// A symbolic link in place of applied.json is refused.
	_ = os.Remove(h.env.Paths.appliedPath())
	target := filepath.Join(h.root, "elsewhere.json")
	h.writeFile(target, string(raw), 0o600)
	if err := os.Symlink(target, h.env.Paths.appliedPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.env.loadApplied(); err == nil {
		t.Fatal("a symbolic link must be refused")
	}
	if err := h.env.saveApplied(&a); err == nil {
		t.Fatal("writing through a symbolic link must be refused")
	}
	if got, _ := os.ReadFile(target); string(got) != string(raw) {
		t.Fatal("the link target was changed")
	}
}

func TestZeroPathsAreRefused(t *testing.T) {
	e := &Env{Runner: newFakeSys(t, Paths{})}
	if out := QuickApply(context.Background(), e, json.RawMessage(`{}`)); out.OK || out.Code != CodeFailed {
		t.Fatalf("%+v", out)
	}
	if _, err := Status(context.Background(), e); err == nil {
		t.Fatal("zero paths")
	}
	if err := ApplyStored(context.Background(), e); err == nil {
		t.Fatal("zero paths")
	}
	p := DefaultPaths()
	p.StateDir = "relative/dir"
	if err := p.Check(); err == nil {
		t.Fatal("relative path")
	}
	if err := DefaultPaths().Check(); err != nil {
		t.Fatal(err)
	}
}
