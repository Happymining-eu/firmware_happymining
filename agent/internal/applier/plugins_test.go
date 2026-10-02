package applier

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
)

func pluginsDoc(rev int, plugins ...map[string]any) map[string]any {
	doc := baseDoc(rev)
	if plugins == nil {
		plugins = []map[string]any{}
	}
	doc["plugins"] = plugins
	return doc
}

func plug(id string, enabled bool, settings map[string]any) map[string]any {
	if settings == nil {
		settings = map[string]any{}
	}
	return map[string]any{"id": id, "enabled": enabled, "settings": settings}
}

const hostileSecret = "k=v $HOME ${X} \"q\" 'a' \\ #c\nsecond line\ttab"

func TestApplyPluginsCommandsAndEnvFiles(t *testing.T) {
	h := newHarness(t)
	p := h.env.Paths
	doc := pluginsDoc(1,
		plug("ollama", true, map[string]any{"models": []any{"hermes3:8b", "bge-m3"}}),
		plug("qdrant", true, nil),
		plug("assistant", true, map[string]any{"bind": "localhost", "workers": 4, "model": "hermes3:8b"}),
	)
	doc["secrets"] = map[string]any{"plugin.assistant.api_key": h.sealFor("plugin.assistant.api_key", hostileSecret)}
	if out := h.apply(doc); !out.OK {
		t.Fatalf("%+v", out)
	}
	up := func(id string) string {
		return DockerPath + " compose -p hm-" + id + " --env-file " + p.envFile(id) + " -f " +
			filepath.Join(p.CatalogDir, id, "compose.yaml") + " up -d"
	}
	want := []string{
		DockerPath + " compose -p hm-ollama down",
		DockerPath + " compose -p hm-qdrant down",
		DockerPath + " compose -p hm-assistant down",
	}
	_ = want // stops happen only for plugins that do not run; none here
	lines := h.sys.lines()
	seq := []string{
		SystemctlPath + " start --no-block " + UnitApply,
		DockerPath + " network inspect hm-appliance",
		DockerPath + " network create hm-appliance",
		DockerPath + " ps --no-trunc --format " + foreignFormat,
		up("ollama"),
		DockerPath + " compose -p hm-ollama exec -T ollama ollama pull hermes3:8b",
		DockerPath + " compose -p hm-ollama exec -T ollama ollama pull bge-m3",
		up("qdrant"),
		up("assistant"),
		DockerPath + " compose -p hm-assistant ps --all --format json",
		DockerPath + " compose -p hm-ollama ps --all --format json",
		DockerPath + " compose -p hm-qdrant ps --all --format json",
	}
	if !reflect.DeepEqual(lines, seq) {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(seq, "\n"))
	}
	env := func(id string) string {
		b, err := os.ReadFile(p.envFile(id))
		if err != nil {
			t.Fatal(err)
		}
		if mode(t, p.envFile(id)) != 0o600 {
			t.Fatalf("%s mode %o", id, mode(t, p.envFile(id)))
		}
		return string(b)
	}
	header := "# Written by the HappyMining helper at every apply. Root only; do not edit.\n"
	if got := env("ollama"); got != header+`HM_SET_MODELS="hermes3:8b bge-m3"`+"\n"+`HM_BIND="0.0.0.0"`+"\n"+
		`HM_PLUGIN_DATA="`+p.pluginData("ollama")+`"`+"\n" {
		t.Fatalf("ollama env:\n%s", got)
	}
	if got := env("assistant"); got != header+`HM_SET_BIND="localhost"`+"\n"+`HM_SET_MODEL="hermes3:8b"`+"\n"+
		`HM_SET_TELEMETRY="false"`+"\n"+`HM_SET_WORKERS="4"`+"\n"+`HM_BIND="127.0.0.1"`+"\n"+
		`HM_PLUGIN_DATA="`+p.pluginData("assistant")+`"`+"\n"+`ASSISTANT_API_KEY=`+encodeEnvValue(hostileSecret)+"\n" {
		t.Fatalf("assistant env:\n%s", got)
	}
	st := h.state()
	for _, id := range []string{"ollama", "qdrant", "assistant"} {
		r, _ := st.findPlugin(id)
		if !r.Started || !r.Desired || r.Observed != appliance.PluginRunning || r.ApplyState != appliance.PluginStarting {
			t.Fatalf("%s: %+v", id, r)
		}
	}
	if r, _ := st.findPlugin("assistant"); !reflect.DeepEqual(r.Ports, []int{18789}) || r.Version != "3" {
		t.Fatalf("%+v", r)
	}
	if st.ApplyStatus != appliance.ApplyApplied {
		t.Fatalf("%s %s", st.ApplyStatus, st.ApplyDetail)
	}
	if mode(t, p.pluginData("ollama")) != 0o700 || mode(t, p.PluginDataRoot) != 0o700 {
		t.Fatal("plugin data directory modes")
	}
	for _, l := range append(lines, h.auditText()) {
		if strings.Contains(l, "second line") || strings.Contains(l, "$HOME ${X}") {
			t.Fatalf("a secret reached a command line or the audit: %q", l)
		}
	}
	assertFixedPrograms(t, h.sys)

	// Removed from the document: taken down (never with -v), record dropped.
	h.sys.reset()
	h.mustApply(pluginsDoc(2, plug("ollama", true, nil), plug("qdrant", false, nil)))
	lines = h.sys.lines()
	if index(lines, DockerPath+" compose -p hm-assistant down") < 0 || index(lines, DockerPath+" compose -p hm-qdrant down") < 0 {
		t.Fatalf("%q", lines)
	}
	for _, l := range lines {
		if strings.Contains(l, " -v") || strings.Contains(l, "--volumes") || strings.Contains(l, "--rmi") || strings.Contains(l, " rm ") {
			t.Fatalf("data-destroying command: %q", l)
		}
	}
	st = h.state()
	if _, ok := st.findPlugin("assistant"); ok {
		t.Fatal("the removed plugin is still recorded")
	}
	if r, _ := st.findPlugin("qdrant"); r.ApplyState != appliance.PluginStopped || r.Started {
		t.Fatalf("%+v", r)
	}
}

func TestVastModeStopsEverythingFirst(t *testing.T) {
	h := newHarness(t)
	h.env.Switches.AllowForeignContainers = true
	h.mustApply(pluginsDoc(1, plug("ollama", true, nil), plug("qdrant", true, nil), plug("assistant", true, nil)))
	doc := pluginsDoc(2, plug("ollama", true, nil), plug("qdrant", true, nil), plug("assistant", true, nil))
	doc["mode"] = "vast"
	doc["nas"] = []map[string]any{nfsEntry("bk", "nas", "/e", "", "write")}
	h.sys.reset()
	h.mustApply(doc)
	lines := h.sys.lines()
	iMount := index(lines, MountPath)
	for _, id := range []string{"assistant", "qdrant", "ollama"} {
		i := index(lines, DockerPath+" compose -p hm-"+id+" down")
		if i < 0 || (iMount >= 0 && i > iMount) {
			t.Fatalf("%s must be stopped before anything else: %q", id, lines)
		}
	}
	// Reverse plan order: dependents first.
	if index(lines, DockerPath+" compose -p hm-assistant down") > index(lines, DockerPath+" compose -p hm-ollama down") {
		t.Fatalf("stop order: %q", lines)
	}
	if count(lines, DockerPath+" network") != 0 || strings.Contains(strings.Join(lines, "\n"), " up -d") {
		t.Fatalf("nothing starts in vast mode: %q", lines)
	}
	st := h.state()
	for _, id := range []string{"ollama", "qdrant", "assistant"} {
		r, _ := st.findPlugin(id)
		if r.ApplyState != appliance.PluginBlocked || r.Started || !strings.Contains(r.ApplyDetail, "vast") {
			t.Fatalf("%s: %+v", id, r)
		}
	}
	if st.Mode != "vast" {
		t.Fatal(st.Mode)
	}
}

func TestBlockingRules(t *testing.T) {
	doc := func() map[string]any {
		d := pluginsDoc(1, plug("ollama", true, nil), plug("qdrant", true, nil), plug("vectorizer", true, nil),
			plug("assistant", true, nil))
		d["nas"] = []map[string]any{smbEntry("docs", "nas", "s", "", "", "read")}
		d["vectorizer"] = map[string]any{"sources": []any{"docs"}, "extensions": []any{"pdf"}, "exclude": []any{},
			"max_file_mib": 64, "embedding_model": "bge-m3", "ocr": false, "answer": map[string]any{"provider": "none"}}
		return d
	}
	t.Run("foreign containers block GPU plugins and their dependents", func(t *testing.T) {
		h := newHarness(t)
		h.sys.foreign = 2
		h.mustApply(doc())
		lines := h.sys.lines()
		if index(lines, DockerPath+" compose -p hm-ollama down") < 0 || strings.Contains(strings.Join(lines, "\n"), "hm-ollama --env-file") {
			t.Fatalf("ollama must be stopped and not started: %q", lines)
		}
		st := h.state()
		if r, _ := st.findPlugin("ollama"); r.ApplyState != appliance.PluginBlocked || !r.GuardBlocked ||
			!strings.Contains(r.ApplyDetail, "2 container(s)") || !strings.Contains(r.ApplyDetail, "not a proof") {
			t.Fatalf("%+v", r)
		}
		if r, _ := st.findPlugin("assistant"); r.ApplyState != appliance.PluginError || !strings.Contains(r.ApplyDetail, "ollama") {
			t.Fatalf("%+v", r)
		}
		if r, _ := st.findPlugin("qdrant"); r.ApplyState != appliance.PluginStarting {
			t.Fatalf("a plugin without GPU starts: %+v", r)
		}
		if st.ApplyStatus != appliance.ApplyPartial || !strings.Contains(st.ApplyDetail, "blocked: ") {
			t.Fatalf("%s %s", st.ApplyStatus, st.ApplyDetail)
		}
		// Once no foreign container runs, the refresh asks for an apply.
		h.sys.foreign = 0
		h.sys.reset()
		h.env.refreshPlugins(context.Background())
		if !h.sys.started(UnitApply) {
			t.Fatalf("%q", h.sys.lines())
		}
	})
	t.Run("unknown container state blocks GPU plugins", func(t *testing.T) {
		h := newHarness(t)
		h.sys.psError = true
		h.mustApply(doc())
		if r, _ := h.state().findPlugin("ollama"); r.ApplyState != appliance.PluginBlocked || !strings.Contains(r.ApplyDetail, "cannot be told") {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("ALLOW_FOREIGN_CONTAINERS", func(t *testing.T) {
		h := newHarness(t)
		h.sys.foreign = 2
		h.env.Switches.AllowForeignContainers = true
		h.mustApply(doc())
		if r, _ := h.state().findPlugin("ollama"); r.ApplyState != appliance.PluginStarting {
			t.Fatalf("%+v", r)
		}
		if count(h.sys.lines(), DockerPath+" ps ") != 0 {
			t.Fatal("no container listing is needed when the guard is off")
		}
	})
	t.Run("unpinned images", func(t *testing.T) {
		h := newHarness(t)
		h.mustApply(doc())
		lines := h.sys.lines()
		r, _ := h.state().findPlugin("vectorizer")
		if r.ApplyState != appliance.PluginBlocked || !strings.Contains(r.ApplyDetail, "ALLOW_UNPINNED_IMAGES") ||
			index(lines, DockerPath+" compose -p hm-vectorizer down") < 0 || index(lines, DockerPath+" build") >= 0 {
			t.Fatalf("%+v %q", r, lines)
		}
	})
	t.Run("ALLOW_UNPINNED_IMAGES builds the vectorizer and writes its configuration", func(t *testing.T) {
		h := newHarness(t)
		p := h.env.Paths
		h.env.Switches.AllowUnpinnedImages = true
		d := doc()
		d["vectorizer"].(map[string]any)["answer"] = map[string]any{"provider": "openai_compatible",
			"base_url": "https://api.example.com/v1", "model": "m-1", "secret": "ai.answer.api_key"}
		d["secrets"] = map[string]any{"ai.answer.api_key": h.sealFor("ai.answer.api_key", "sk-test-key")}
		h.mustApply(d)
		lines := h.sys.lines()
		iInspect := index(lines, DockerPath+" image inspect --format {{.Id}} happymining/vectorizer:1")
		iBuild := index(lines, DockerPath+" build -t happymining/vectorizer:1 "+filepath.Join(p.BuildRoot, "vectorizer"))
		iUp := index(lines, DockerPath+" compose -p hm-vectorizer --env-file")
		iQdrant := index(lines, DockerPath+" compose -p hm-qdrant --env-file")
		if iInspect < 0 || iBuild < iInspect || iUp < iBuild || iQdrant > iUp {
			t.Fatalf("%q", lines)
		}
		raw, err := os.ReadFile(filepath.Join(p.vectorizerConfigDir(), "vectorizer.json"))
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]any
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatal(err)
		}
		if cfg["ollama_url"] != "http://ollama:11434" || cfg["qdrant_url"] != "http://qdrant:6333" ||
			cfg["collection"] != "happymining_docs" || !reflect.DeepEqual(cfg["source_paths"], map[string]any{"docs": "/srv/happymining/nas/docs"}) ||
			cfg["answer"].(map[string]any)["secret"] != "ai.answer.api_key" || strings.Contains(string(raw), "sk-test-key") {
			t.Fatalf("%s", raw)
		}
		token, err := os.ReadFile(filepath.Join(p.vectorizerConfigDir(), "token"))
		if err != nil || !validToken(strings.TrimSpace(string(token))) {
			t.Fatalf("token %q %v", token, err)
		}
		// The container runs as an unprivileged user: it reads its
		// configuration through its group, which may not write it.
		for path, want := range map[string]os.FileMode{
			p.vectorizerConfigDir():                                   0o750,
			filepath.Join(p.vectorizerConfigDir(), "vectorizer.json"): 0o640,
			filepath.Join(p.vectorizerConfigDir(), "token"):           0o640,
		} {
			fi, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			st := fi.Sys().(*syscall.Stat_t)
			if fi.Mode().Perm() != want || int(st.Gid) != testGID || st.Uid != uint32(os.Getuid()) {
				t.Fatalf("%s: mode %v gid %d uid %d, want %v gid %d", path, fi.Mode().Perm(), st.Gid, st.Uid, want, testGID)
			}
		}
		if index(lines, DockerPath+" compose -p hm-vectorizer restart") >= 0 {
			t.Fatalf("restarted on its first start: %q", lines)
		}
		env, _ := os.ReadFile(p.envFile("vectorizer"))
		if !strings.Contains(string(env), `HM_ANSWER_API_KEY="sk-test-key"`) {
			t.Fatalf("%s", env)
		}
		// The token is kept across applies; the image is not built again.
		h.sys.reset()
		d["revision"] = 2
		h.mustApply(d)
		token2, _ := os.ReadFile(filepath.Join(p.vectorizerConfigDir(), "token"))
		if string(token2) != string(token) || index(h.sys.lines(), DockerPath+" build") >= 0 {
			t.Fatal("token replaced or image rebuilt")
		}
		// The same configuration: the running vectorizer is left alone.
		if index(h.sys.lines(), DockerPath+" compose -p hm-vectorizer restart") >= 0 {
			t.Fatalf("restarted without a change: %q", h.sys.lines())
		}
		// A changed configuration: the vectorizer reads it only when it
		// starts, so it is restarted after `up -d`.
		h.sys.reset()
		d["revision"] = 3
		d["vectorizer"].(map[string]any)["max_file_mib"] = 32
		h.mustApply(d)
		after := h.sys.lines()
		iUp2 := index(after, DockerPath+" compose -p hm-vectorizer --env-file")
		iRestart := index(after, DockerPath+" compose -p hm-vectorizer restart")
		if iUp2 < 0 || iRestart < iUp2 {
			t.Fatalf("not restarted after a configuration change: %q", after)
		}
	})
}

func TestPartialFailureContinues(t *testing.T) {
	h := newHarness(t)
	h.sys.override = func(argv []string) (fakeResp, bool) {
		if strings.Join(argv, " ") == DockerPath+" compose -p hm-qdrant --env-file "+h.env.Paths.envFile("qdrant")+" -f "+
			filepath.Join(h.env.Paths.CatalogDir, "qdrant", "compose.yaml")+" up -d" {
			return fakeResp{code: 1, stderr: "pulling...\nError: port is already allocated\n"}, true
		}
		return fakeResp{}, false
	}
	h.mustApply(pluginsDoc(1, plug("qdrant", true, nil), plug("ollama", true, nil), plug("assistant", true, nil)))
	st := h.state()
	if r, _ := st.findPlugin("qdrant"); r.ApplyState != appliance.PluginError || !strings.Contains(r.ApplyDetail, "port is already allocated") || r.Started {
		t.Fatalf("%+v", r)
	}
	for _, id := range []string{"ollama", "assistant"} {
		if r, _ := st.findPlugin(id); r.ApplyState != appliance.PluginStarting {
			t.Fatalf("a failing item must not stop the others: %s %+v", id, r)
		}
	}
	if st.ApplyStatus != appliance.ApplyPartial || !strings.Contains(st.ApplyDetail, "qdrant") {
		t.Fatalf("%s %q", st.ApplyStatus, st.ApplyDetail)
	}
}

func TestPostStartRetriesAndFailure(t *testing.T) {
	h := newHarness(t)
	fails := 2
	h.sys.override = func(argv []string) (fakeResp, bool) {
		if strings.Contains(strings.Join(argv, " "), " exec -T ollama ollama pull ") && fails > 0 {
			fails--
			return fakeResp{code: 1, stderr: "Error: could not connect to ollama app"}, true
		}
		return fakeResp{}, false
	}
	h.mustApply(pluginsDoc(1, plug("ollama", true, map[string]any{"models": []any{"bge-m3"}})))
	if !reflect.DeepEqual(h.slept, []time.Duration{10 * time.Second, 30 * time.Second}) {
		t.Fatalf("waits %v", h.slept)
	}
	if r, _ := h.state().findPlugin("ollama"); r.ApplyState != appliance.PluginStarting {
		t.Fatalf("%+v", r)
	}
	// Always failing: error, but it was started (recorded so).
	h2 := newHarness(t)
	h2.sys.override = func(argv []string) (fakeResp, bool) {
		if strings.Contains(strings.Join(argv, " "), " exec -T ") {
			return fakeResp{code: 1, stderr: "pull model manifest: file does not exist"}, true
		}
		return fakeResp{}, false
	}
	h2.mustApply(pluginsDoc(1, plug("ollama", true, map[string]any{"models": []any{"bge-m3"}})))
	r, _ := h2.state().findPlugin("ollama")
	if r.ApplyState != appliance.PluginError || !r.Started || !strings.Contains(r.ApplyDetail, "post-start command 1 of 1 (service ollama) failed") {
		t.Fatalf("%+v", r)
	}
	if n := count(h2.sys.lines(), DockerPath+" compose -p hm-ollama exec -T ollama ollama pull bge-m3"); n != 3 {
		t.Fatalf("attempts %d", n)
	}
	// Reported as error even though the container runs.
	state, detail := reportedPluginState(r)
	if state != appliance.PluginError || !strings.Contains(detail, "post-start") {
		t.Fatal(state, detail)
	}
}

func TestPluginSecretProblems(t *testing.T) {
	cases := map[string]struct {
		secrets map[string]any
		want    string
	}{
		"optional secret absent": {secrets: nil, want: ""},
		"optional secret unreadable": {secrets: map[string]any{"plugin.assistant.api_key": func() string {
			return newHarness(t).sealFor("plugin.assistant.api_key", "x")
		}()}, want: "unreadable"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			doc := pluginsDoc(1, plug("ollama", true, nil), plug("assistant", true, nil))
			if tc.secrets != nil {
				doc["secrets"] = tc.secrets
			}
			h.mustApply(doc)
			r, _ := h.state().findPlugin("assistant")
			if tc.want == "" {
				if r.ApplyState != appliance.PluginStarting {
					t.Fatalf("%+v", r)
				}
				env, _ := os.ReadFile(h.env.Paths.envFile("assistant"))
				if strings.Contains(string(env), "ASSISTANT_API_KEY") {
					t.Fatal("an absent optional secret is not written")
				}
				return
			}
			if r.ApplyState != appliance.PluginError || !strings.Contains(r.ApplyDetail, tc.want) {
				t.Fatalf("%+v", r)
			}
			if strings.Contains(strings.Join(h.sys.lines(), "\n"), "hm-assistant --env-file") {
				t.Fatal("started without its secret")
			}
		})
	}
	t.Run("secret that an env file cannot hold", func(t *testing.T) {
		h := newHarness(t)
		doc := pluginsDoc(1, plug("ollama", true, nil), plug("assistant", true, nil))
		doc["secrets"] = map[string]any{"plugin.assistant.api_key": h.sealFor("plugin.assistant.api_key", "a\x00b")}
		h.mustApply(doc)
		r, _ := h.state().findPlugin("assistant")
		if r.ApplyState != appliance.PluginError || !strings.Contains(r.ApplyDetail, "NUL") || strings.Contains(r.ApplyDetail, "a\x00b") {
			t.Fatalf("%+v", r)
		}
	})
}

func TestPluginSwitchOffAndNoDocker(t *testing.T) {
	h := newHarness(t)
	h.env.Switches.AllowPlugins = false
	h.mustApply(pluginsDoc(1, plug("qdrant", true, nil)))
	if count(h.sys.lines(), DockerPath) != 0 {
		t.Fatalf("%q", h.sys.lines())
	}
	st := h.state()
	if r, _ := st.findPlugin("qdrant"); r.ApplyState != appliance.PluginBlocked || !strings.Contains(r.ApplyDetail, "ALLOW_PLUGINS") {
		t.Fatalf("%+v", r)
	}
	if st.ApplyStatus != appliance.ApplyDisabled {
		t.Fatal(st.ApplyStatus)
	}

	h = newHarness(t)
	h.env.HasDocker = func() bool { return false }
	h.mustApply(pluginsDoc(1, plug("qdrant", true, nil)))
	if count(h.sys.lines(), DockerPath) != 0 {
		t.Fatalf("%q", h.sys.lines())
	}
	if r, _ := h.state().findPlugin("qdrant"); r.ApplyState != appliance.PluginError || !strings.Contains(r.ApplyDetail, "Docker is not installed") {
		t.Fatalf("%+v", r)
	}
}

// Plugins started while ALLOW_PLUGINS was on must not keep running against a
// renter when the switch goes off at the same time as the mode becomes vast:
// stopping HappyMining's own projects needs no switch, starting does. The
// state never says "stopped" for a plugin that was not stopped.
func TestVastModeStopsStartedPluginsEvenWithTheSwitchOff(t *testing.T) {
	h := newHarness(t)
	h.mustApply(pluginsDoc(1, plug("qdrant", true, nil), plug("ollama", true, nil)))
	if r, _ := h.state().findPlugin("qdrant"); !r.Started {
		t.Fatalf("qdrant was not started: %+v", r)
	}

	h.env.Switches.AllowPlugins = false
	h.sys.reset()
	vast := pluginsDoc(2, plug("qdrant", true, nil), plug("ollama", true, nil))
	vast["mode"] = "vast"
	h.mustApply(vast)
	lines := h.sys.lines()
	for _, id := range []string{"qdrant", "ollama"} {
		if index(lines, DockerPath+" compose -p hm-"+id+" down") < 0 {
			t.Fatalf("%s was not stopped: %q", id, lines)
		}
		r, _ := h.state().findPlugin(id)
		if r.Started || r.ApplyState != appliance.PluginStopped {
			t.Fatalf("%s: %+v", id, r)
		}
	}
	for _, line := range lines {
		if strings.HasPrefix(line, DockerPath) &&
			(strings.Contains(line, " up ") || strings.Contains(line, " start") || strings.Contains(line, " -v")) {
			t.Fatalf("with the switch off only stopping is allowed: %q", line)
		}
	}

	// Both switches off at once: the apply still runs, to stop what was started.
	h = newHarness(t)
	h.mustApply(pluginsDoc(1, plug("qdrant", true, nil)))
	h.env.Switches.AllowPlugins, h.env.Switches.AllowNAS = false, false
	h.sys.reset()
	vast = pluginsDoc(2, plug("qdrant", true, nil))
	vast["mode"] = "vast"
	h.apply(vast)
	if index(h.sys.lines(), DockerPath+" compose -p hm-qdrant down") < 0 {
		t.Fatalf("with both switches off a started plugin kept running in vast mode: %q", h.sys.lines())
	}
	if r, _ := h.state().findPlugin("qdrant"); r.Started || r.ApplyState != appliance.PluginStopped {
		t.Fatalf("%+v", r)
	}
	// Nothing started, both switches off: nothing is applied at all.
	h = newHarness(t)
	h.env.Switches.AllowPlugins, h.env.Switches.AllowNAS = false, false
	if out := h.apply(vast); out.OK || out.Code != CodeDisabled || h.sys.started(UnitApply) {
		t.Fatalf("%+v %q", out, h.sys.lines())
	}

	// A plugin the document still runs is left alone, and not reported as stopped.
	h = newHarness(t)
	h.mustApply(pluginsDoc(1, plug("qdrant", true, nil)))
	h.env.Switches.AllowPlugins = false
	h.sys.reset()
	h.mustApply(pluginsDoc(2, plug("qdrant", true, nil)))
	if count(h.sys.lines(), DockerPath) != 0 {
		t.Fatalf("%q", h.sys.lines())
	}
	if r, _ := h.state().findPlugin("qdrant"); r.ApplyState != appliance.PluginBlocked || !r.Started ||
		!strings.Contains(r.ApplyDetail, "left as it is") {
		t.Fatalf("%+v", r)
	}

	// A plugin that left the document is stopped and forgotten.
	h = newHarness(t)
	h.mustApply(pluginsDoc(1, plug("qdrant", true, nil), plug("ollama", true, nil)))
	h.env.Switches.AllowPlugins = false
	h.sys.reset()
	h.mustApply(pluginsDoc(2, plug("ollama", false, nil)))
	if index(h.sys.lines(), DockerPath+" compose -p hm-qdrant down") < 0 || index(h.sys.lines(), DockerPath+" compose -p hm-ollama down") < 0 {
		t.Fatalf("%q", h.sys.lines())
	}
	if _, ok := h.state().findPlugin("qdrant"); ok {
		t.Fatal("qdrant is still recorded")
	}
}

func TestModeAndDisabledReasons(t *testing.T) {
	h := newHarness(t)
	doc := pluginsDoc(1, plug("ollama", true, nil), plug("qdrant", false, nil), plug("assistant", true, nil))
	doc["mode"] = "vectorize"
	h.mustApply(doc)
	st := h.state()
	if r, _ := st.findPlugin("assistant"); r.ApplyState != appliance.PluginBlocked || !strings.Contains(r.ApplyDetail, "vectorize") {
		t.Fatalf("%+v", r)
	}
	if r, _ := st.findPlugin("qdrant"); r.ApplyState != appliance.PluginStopped {
		t.Fatalf("%+v", r)
	}
	if r, _ := st.findPlugin("ollama"); r.ApplyState != appliance.PluginStarting {
		t.Fatalf("%+v", r)
	}
}

func TestBindAddress(t *testing.T) {
	cat, err := appliance.LoadCatalog(fixtureCatalog())
	if err != nil {
		t.Fatal(err)
	}
	assistant, _ := cat.Plugin("assistant")
	ollama, _ := cat.Plugin("ollama")
	for _, c := range []struct {
		entry *appliance.Plugin
		cfg   map[string]any
		want  string
	}{
		{ollama, nil, "0.0.0.0"},
		{assistant, map[string]any{"bind": "lan"}, "0.0.0.0"},
		{assistant, map[string]any{"bind": "localhost"}, "127.0.0.1"},
		{assistant, map[string]any{}, "0.0.0.0"}, // the fixture's default is lan
		{assistant, map[string]any{"bind": "everywhere"}, "127.0.0.1"},
	} {
		if got := bindAddress(c.entry, appliance.PluginConfig{Settings: c.cfg}); got != c.want {
			t.Errorf("%s %v: %s", c.entry.ID, c.cfg, got)
		}
	}
}

func TestComposePsParsing(t *testing.T) {
	ndjson := `{"ID":"1","Name":"hm-x-a-1","Service":"a","State":"running","Health":"","ExitCode":0,"Publishers":[{"URL":"0.0.0.0","TargetPort":80,"PublishedPort":8080,"Protocol":"tcp"}]}
{"ID":"2","Name":"hm-x-b-1","Service":"b","State":"running","Health":"starting","ExitCode":0,"Publishers":null}
`
	array := `[{"ID":"1","Name":"hm-x-a-1","Service":"a","State":"exited","Health":"","ExitCode":137,"Publishers":null}]`
	for name, c := range map[string]struct {
		out, state, detail string
	}{
		"ndjson starting":   {ndjson, appliance.PluginStarting, ""},
		"array crashed":     {array, appliance.PluginError, "service a exited with code 137"},
		"empty":             {"", appliance.PluginStopped, ""},
		"healthy":           {`{"Service":"a","State":"running","Health":"healthy"}`, appliance.PluginRunning, ""},
		"unhealthy":         {`{"Service":"a","State":"running","Health":"unhealthy"}`, appliance.PluginError, "service a is unhealthy"},
		"restarting":        {`{"Service":"a","State":"restarting"}`, appliance.PluginError, "service a keeps restarting"},
		"stopped cleanly":   {`{"Service":"a","State":"exited","ExitCode":0}`, appliance.PluginStopped, ""},
		"partly running":    {`{"Service":"a","State":"running"}` + "\n" + `{"Service":"b","State":"exited"}`, appliance.PluginError, "some services are not running"},
		"control in a name": {`{"Service":"a\u001b[31m","State":"restarting"}`, appliance.PluginError, "service a [31m keeps restarting"},
	} {
		list, err := parseComposePs([]byte(c.out))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		state, detail := observedState(list)
		if state != c.state || detail != c.detail {
			t.Errorf("%s: %s %q", name, state, detail)
		}
	}
	if _, err := parseComposePs([]byte("not json")); err == nil {
		t.Fatal("garbage must be an error")
	}
}
