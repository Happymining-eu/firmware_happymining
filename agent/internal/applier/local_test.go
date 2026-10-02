package applier

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPurge(t *testing.T) {
	setup := func(t *testing.T) *harness {
		h := newHarness(t)
		h.env.Switches.AllowForeignContainers = true
		h.mustApply(pluginsDoc(1, plug("ollama", true, nil), plug("assistant", true, nil)))
		h.sys.volumes["hm-assistant_data"] = true
		h.sys.volumes["hm-assistantx_data"] = true // another plugin's
		h.sys.volumes["unrelated"] = true
		h.writeFile(filepath.Join(h.env.Paths.pluginData("assistant"), "file"), "data", 0o600)
		return h
	}
	t.Run("in the document", func(t *testing.T) {
		h := setup(t)
		h.sys.reset()
		var prompt bytes.Buffer
		if err := Purge(context.Background(), h.env, "assistant", strings.NewReader("assistant\n"), &prompt); err == nil ||
			!strings.Contains(err.Error(), "document") {
			t.Fatal(err)
		}
		if len(h.sys.lines()) != 0 {
			t.Fatalf("%q", h.sys.lines())
		}
	})
	t.Run("removed, stopped, confirmed", func(t *testing.T) {
		h := setup(t)
		h.mustApply(pluginsDoc(2, plug("ollama", true, nil)))
		h.sys.reset()
		var prompt bytes.Buffer
		if err := Purge(context.Background(), h.env, "assistant", strings.NewReader("assistant\n"), &prompt); err != nil {
			t.Fatal(err)
		}
		want := []string{
			DockerPath + " compose -p hm-assistant ps --all --format json",
			DockerPath + " compose -p hm-assistant down",
			DockerPath + " volume ls --quiet --filter label=com.docker.compose.project=hm-assistant",
			DockerPath + " volume rm hm-assistant_data",
		}
		if strings.Join(h.sys.lines(), "\n") != strings.Join(want, "\n") {
			t.Fatalf("%q", h.sys.lines())
		}
		if _, err := os.Lstat(h.env.Paths.pluginData("assistant")); err == nil {
			t.Fatal("the data directory remains")
		}
		if _, err := os.Lstat(h.env.Paths.envFile("assistant")); err == nil {
			t.Fatal("the env file remains")
		}
		if !h.sys.volumes["hm-assistantx_data"] || !h.sys.volumes["unrelated"] {
			t.Fatal("another volume was removed")
		}
		if _, err := os.Lstat(h.env.Paths.pluginData("ollama")); err != nil {
			t.Fatal("another plugin's data was touched")
		}
	})
	t.Run("not confirmed", func(t *testing.T) {
		h := setup(t)
		h.mustApply(pluginsDoc(2, plug("ollama", true, nil)))
		h.sys.reset()
		var prompt bytes.Buffer
		if err := Purge(context.Background(), h.env, "assistant", strings.NewReader("yes\n"), &prompt); err == nil {
			t.Fatal("must not be confirmed")
		}
		if count(h.sys.lines(), DockerPath+" volume rm") != 0 || count(h.sys.lines(), DockerPath+" compose -p hm-assistant down") != 0 {
			t.Fatalf("%q", h.sys.lines())
		}
		if _, err := os.Lstat(filepath.Join(h.env.Paths.pluginData("assistant"), "file")); err != nil {
			t.Fatal("data deleted without confirmation")
		}
	})
	t.Run("still running", func(t *testing.T) {
		h := setup(t)
		h.mustApply(pluginsDoc(2, plug("ollama", true, nil)))
		h.sys.projects["assistant"] = "running" // started by hand again
		var prompt bytes.Buffer
		if err := Purge(context.Background(), h.env, "assistant", strings.NewReader("assistant\n"), &prompt); err == nil ||
			!strings.Contains(err.Error(), "stopped") {
			t.Fatal(err)
		}
	})
	t.Run("data directory is a link", func(t *testing.T) {
		h := setup(t)
		h.mustApply(pluginsDoc(2, plug("ollama", true, nil)))
		target := filepath.Join(h.root, "precious")
		h.writeFile(filepath.Join(target, "keep"), "keep", 0o600)
		_ = os.RemoveAll(h.env.Paths.pluginData("assistant"))
		if err := os.Symlink(target, h.env.Paths.pluginData("assistant")); err != nil {
			t.Fatal(err)
		}
		var prompt bytes.Buffer
		_ = Purge(context.Background(), h.env, "assistant", strings.NewReader("assistant\n"), &prompt)
		if _, err := os.Stat(filepath.Join(target, "keep")); err != nil {
			t.Fatal("a link was followed")
		}
	})
	t.Run("invalid id", func(t *testing.T) {
		h := setup(t)
		var prompt bytes.Buffer
		for _, id := range []string{"../x", "", "A", "x/y"} {
			if err := Purge(context.Background(), h.env, id, strings.NewReader(id+"\n"), &prompt); err == nil {
				t.Fatalf("%q accepted", id)
			}
		}
	})
}

func TestVectorizerToken(t *testing.T) {
	h := newHarness(t)
	var a, b bytes.Buffer
	if err := VectorizerToken(h.env, &a); err != nil {
		t.Fatal(err)
	}
	if err := VectorizerToken(h.env, &b); err != nil {
		t.Fatal(err)
	}
	tok := strings.TrimSpace(a.String())
	if !validToken(tok) || a.String() != b.String() {
		t.Fatalf("%q %q", a.String(), b.String())
	}
	path := filepath.Join(h.env.Paths.vectorizerConfigDir(), "token")
	// Readable by the container's group, writable by root only.
	if mode(t, path) != 0o640 || mode(t, h.env.Paths.vectorizerConfigDir()) != 0o750 {
		t.Fatal("modes")
	}
	if strings.Contains(h.auditText(), tok) {
		t.Fatal("the token reached the audit")
	}
	// A valid token written root-only by an earlier version is kept, and
	// given to the container's group.
	h.writeFile(path, tok+"\n", 0o600)
	var kept bytes.Buffer
	if err := VectorizerToken(h.env, &kept); err != nil || strings.TrimSpace(kept.String()) != tok || mode(t, path) != 0o640 {
		t.Fatalf("kept %q, mode %v, %v", kept.String(), mode(t, path), err)
	}
	// A token file that is not a valid token is replaced.
	h.writeFile(path, "short\n", 0o600)
	var c bytes.Buffer
	_ = VectorizerToken(h.env, &c)
	if strings.TrimSpace(c.String()) == "short" || !validToken(strings.TrimSpace(c.String())) {
		t.Fatal(c.String())
	}
}

func TestScrubber(t *testing.T) {
	s := &scrubber{}
	s.add([]byte("hunter2"))
	s.add([]byte("p@ss word"))
	got := s.scrub("auth failed for hunter2; retry with p@ss word or hunter2x")
	if got != "auth failed for [redacted]; retry with [redacted] or [redacted]x" {
		t.Fatal(got)
	}
	var nilScrubber *scrubber
	if nilScrubber.scrub("x") != "x" {
		t.Fatal("nil")
	}
}

// TestSecretsNeverLeak runs applies, failures that echo the secrets on
// stderr, jobs and the status, and looks for every plaintext in every
// captured output: command lines, audit lines, state.json, results.
func TestSecretsNeverLeak(t *testing.T) {
	h := newHarness(t)
	h.env.Switches.AllowUnpinnedImages = true
	h.env.Switches.AllowForeignContainers = true
	plain := map[string]string{
		"nas.docs.password":        "NASPASS-1f2e3d",
		"ai.answer.api_key":        "ANSWERKEY-9a8b7c",
		"plugin.assistant.api_key": "PLUGINKEY-445566",
	}
	doc := fullDoc(h, 1)
	for name, v := range plain {
		doc["secrets"].(map[string]any)[name] = h.sealFor(name, v)
	}
	// Every command that could see a secret fails and echoes all of them.
	echo := strings.Join([]string{plain["nas.docs.password"], plain["ai.answer.api_key"], plain["plugin.assistant.api_key"]}, " ")
	h.sys.override = func(argv []string) (fakeResp, bool) {
		line := strings.Join(argv, " ")
		if strings.HasPrefix(line, MountPath) || strings.Contains(line, " up -d") || strings.Contains(line, " exec -T ") {
			return fakeResp{code: 1, stderr: "error: " + echo + "\n"}, true
		}
		return fakeResp{}, false
	}
	out := QuickApply(context.Background(), h.env, mustJSON(t, doc))
	if !out.OK {
		t.Fatalf("%+v", out)
	}
	if err := ApplyStored(context.Background(), h.env); err != nil {
		t.Fatal(err)
	}
	h.sys.override = nil
	_ = RunJob(context.Background(), h.env, "vectorize_sync")
	res, err := Status(context.Background(), h.env)
	if err != nil {
		t.Fatal(err)
	}
	result, _ := json.Marshal(res)
	stateJSON, _ := os.ReadFile(h.env.Paths.statePath())
	applied, _ := os.ReadFile(h.env.Paths.appliedPath())
	outcome, _ := json.Marshal(out)
	captured := map[string]string{
		"argv": strings.Join(h.sys.lines(), "\n"), "audit": h.auditText(), "state.json": string(stateJSON),
		"applied.json": string(applied), "status": string(result), "outcome": string(outcome),
	}
	for where, text := range captured {
		for name, v := range plain {
			if strings.Contains(text, v) {
				t.Errorf("%s holds the plaintext of %s", where, name)
			}
		}
	}
	if !strings.Contains(string(stateJSON), "[redacted]") {
		t.Fatalf("the echoed secrets were expected to be redacted in the details:\n%s", stateJSON)
	}
}
