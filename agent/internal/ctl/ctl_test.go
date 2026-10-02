package ctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/client"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/credential"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/execx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/identity"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/preflight"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/testapi"
)

type fixture struct {
	t        *testing.T
	api      *testapi.Server
	srv      *httptest.Server
	stateDir string
	config   string
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	env      Env
	typed    string
	confirm  bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, api: testapi.New(), stateDir: filepath.Join(t.TempDir(), "state")}
	f.srv = httptest.NewServer(f.api.Handler())
	t.Cleanup(f.srv.Close)
	f.config = filepath.Join(t.TempDir(), "agent.env")
	f.writeConfig(f.srv.URL)
	runner := execx.NewFake()
	for unit, state := range map[string]string{"happymining-agent": "active", "docker": "active", "vastai": "inactive", "nvidia-persistenced": "failed"} {
		runner.On("/usr/bin/systemctl is-active "+unit+".service", execx.FakeResponse{Stdout: state + "\n"})
	}
	runner.On("/usr/bin/systemctl show --property=LoadState --value vastai.service", execx.FakeResponse{Stdout: "not-found\n"})
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr/bin/systemctl"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), 0o644)
	f.env = Env{
		Stdout: &f.stdout, Stderr: &f.stderr, Runner: runner, Root: root,
		ReadCode: func() (string, error) {
			if f.typed == "" {
				return "", errors.New("no input")
			}
			return f.typed, nil
		},
		Confirm: func(string, string) bool { return f.confirm },
		PreflightEnv: func(api *client.Client, offline bool) preflight.Env {
			env := preflight.HostEnv(api, offline)
			env.Root = root
			env.Runner = runner
			env.Statfs = func(string) (uint64, uint64, error) { return 500e9, 400e9, nil }
			// Keep the test hermetic: no real outbound probe.
			env.ProbeHTTPS = func(context.Context, string) error { return nil }
			return env
		},
	}
	return f
}

func (f *fixture) writeConfig(apiURL string) {
	f.t.Helper()
	content := fmt.Sprintf("HM_API_URL=%s\nHM_STATE_DIR=%s\nHM_ALLOW_INSECURE_LOOPBACK=1\n", apiURL, f.stateDir)
	if err := os.WriteFile(f.config, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) run(args ...string) int {
	f.stdout.Reset()
	f.stderr.Reset()
	return Run(append([]string{"--config", f.config}, args...), f.env)
}

func (f *fixture) output() string { return f.stdout.String() + f.stderr.String() }

func TestIdentityInit(t *testing.T) {
	f := newFixture(t)
	if code := f.run("identity", "init"); code != ExitOK || !strings.Contains(f.stdout.String(), "created") {
		t.Fatalf("%d %s", code, f.output())
	}
	path := identity.Path(f.stateDir)
	first, _ := os.ReadFile(path)
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("identity mode %04o", fi.Mode().Perm())
	}
	if code := f.run("identity", "init"); code != ExitOK || !strings.Contains(f.stdout.String(), "left unchanged") {
		t.Fatalf("%d %s", code, f.output())
	}
	second, _ := os.ReadFile(path)
	if !bytes.Equal(first, second) {
		t.Fatal("identity init must be idempotent")
	}
	// --force-regenerate alone is refused.
	if code := f.run("identity", "init", "--force-regenerate"); code != ExitUsage {
		t.Fatalf("exit %d", code)
	}
	if code := f.run("identity", "init", "--i-understand-this-requires-re-enrollment"); code != ExitUsage {
		t.Fatalf("exit %d", code)
	}
	third, _ := os.ReadFile(path)
	if !bytes.Equal(first, third) {
		t.Fatal("the identity changed without the confirmation flag")
	}
	if code := f.run("identity", "init", "--force-regenerate", "--i-understand-this-requires-re-enrollment"); code != ExitOK {
		t.Fatalf("%d %s", code, f.output())
	}
	fourth, _ := os.ReadFile(path)
	if bytes.Equal(first, fourth) {
		t.Fatal("the identity was not regenerated")
	}
}

func TestPairWithPromptedCode(t *testing.T) {
	f := newFixture(t)
	code := f.api.NewPairingCode()
	f.typed = "  " + strings.ToLower(strings.ReplaceAll(code, "-", " ")) + "\n"
	if exit := f.run("pair"); exit != ExitOK {
		t.Fatalf("%d %s", exit, f.output())
	}
	cred, err := credential.Load(credential.Path(f.stateDir))
	if err != nil {
		t.Fatal(err)
	}
	out := f.output()
	for _, want := range []string{"Paired.", cred.DeviceID, cred.MachineID, cred.CredentialID} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	secretPart := code[len("HM-XXXXXX-"):]
	for _, leak := range []string{cred.Token, cred.Token[strings.IndexByte(cred.Token, '.')+1:], code, secretPart, strings.ToLower(secretPart)} {
		if strings.Contains(out, leak) {
			t.Errorf("output leaks a secret (%d characters)", len(leak))
		}
	}
	if !strings.Contains(out, code[:9]+"-****-****-****-****") {
		t.Errorf("the masked code (locator only) should be shown:\n%s", out)
	}
	// Nothing on disk contains the pairing code.
	_ = filepath.Walk(f.stateDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			data, _ := os.ReadFile(path)
			if bytes.Contains(data, []byte(secretPart)) || bytes.Contains(bytes.ToUpper(data), []byte(strings.ReplaceAll(code, "-", ""))) {
				t.Errorf("%s contains the pairing code", path)
			}
			if info.Mode().Perm()&0o077 != 0 {
				t.Errorf("%s has mode %04o", path, info.Mode().Perm())
			}
		}
		return nil
	})
	d, ok := f.api.Device(cred.DeviceID)
	if !ok || !strings.HasPrefix(d.Fingerprint, "sha256:") {
		t.Fatalf("server-side device: %+v", d)
	}
	if cred.APIURL != f.srv.URL {
		t.Fatalf("api url in the credential: %q", cred.APIURL)
	}

	// Already paired: refuse, and do not consume another code.
	other := f.api.NewPairingCode()
	if exit := f.run("pair", "--code", other); exit != ExitFail || !strings.Contains(f.stderr.String(), "already paired") {
		t.Fatalf("%d %s", exit, f.output())
	}
	again, _ := credential.Load(credential.Path(f.stateDir))
	if again.Token != cred.Token {
		t.Fatal("the existing credential was replaced")
	}
	if len(f.api.DeviceIDs()) != 1 {
		t.Fatal("a second enrollment happened")
	}
}

func TestPairFailures(t *testing.T) {
	f := newFixture(t)
	// Wrong code: generic failure, nothing stored, the code is not echoed.
	if exit := f.run("pair", "--code", "HM-000000-0000-0000-0000-0000"); exit != ExitFail {
		t.Fatalf("exit %d", exit)
	}
	if !strings.Contains(f.stderr.String(), "pairing failed") || strings.Contains(f.output(), "0000-0000-0000-0000") {
		t.Fatalf("output: %s", f.output())
	}
	if _, err := credential.Load(credential.Path(f.stateDir)); !errors.Is(err, credential.ErrNotPaired) {
		t.Fatalf("a failed pairing must not leave a credential: %v", err)
	}
	// Used code.
	code := f.api.NewPairingCode()
	if exit := f.run("pair", "--code", code); exit != ExitOK {
		t.Fatalf("%d %s", exit, f.output())
	}
	if exit := f.run("unpair", "--yes"); exit != ExitOK {
		t.Fatalf("%d %s", exit, f.output())
	}
	if exit := f.run("pair", "--code", code); exit != ExitFail || !strings.Contains(f.stderr.String(), "pairing failed") {
		t.Fatalf("a used code must fail: %d %s", exit, f.output())
	}
	// Expired code.
	expired := f.api.NewPairingCode()
	f.api.ExpireCode(expired)
	if exit := f.run("pair", "--code", expired); exit != ExitFail {
		t.Fatalf("an expired code must fail: %d", exit)
	}
	// Malformed input never reaches the API.
	before := len(f.api.DeviceIDs())
	if exit := f.run("pair", "--code", "hello"); exit != ExitFail || !strings.Contains(f.stderr.String(), "does not look like a pairing code") {
		t.Fatalf("%d %s", exit, f.output())
	}
	// No code typed.
	f.typed = ""
	if exit := f.run("pair"); exit != ExitFail {
		t.Fatalf("exit %d", exit)
	}
	if len(f.api.DeviceIDs()) != before {
		t.Fatal("unexpected enrollment")
	}
}

func TestPairRefusesInsecureURL(t *testing.T) {
	f := newFixture(t)
	code := f.api.NewPairingCode()
	if exit := f.run("pair", "--api-url", "http://api.example.test", "--code", code); exit != ExitFail {
		t.Fatalf("plain HTTP to a remote host must be refused: %d", exit)
	}
	// The pairing code must not have been spent on the refused URL.
	if exit := f.run("pair", "--api-url", f.srv.URL, "--code", code); exit != ExitOK {
		t.Fatalf("%d %s", exit, f.output())
	}
}

func TestPairCodeIsNotReadFromTheEnvironment(t *testing.T) {
	f := newFixture(t)
	code := f.api.NewPairingCode()
	for _, name := range []string{"HM_PAIRING_CODE", "HM_CODE", "PAIRING_CODE", "HAPPYMINING_PAIRING_CODE"} {
		t.Setenv(name, code)
	}
	f.typed = ""
	if exit := f.run("pair"); exit != ExitFail {
		t.Fatalf("a pairing code from the environment was accepted: %s", f.output())
	}
}

func TestStatus(t *testing.T) {
	f := newFixture(t)
	if exit := f.run("status"); exit != ExitOK || !strings.Contains(f.stdout.String(), "not paired") {
		t.Fatalf("%d %s", exit, f.output())
	}
	if exit := f.run("pair", "--code", f.api.NewPairingCode()); exit != ExitOK {
		t.Fatal(f.output())
	}
	cred, _ := credential.Load(credential.Path(f.stateDir))
	spoolDir := filepath.Join(f.stateDir, "spool")
	_ = os.MkdirAll(spoolDir, 0o750)
	_ = os.WriteFile(filepath.Join(spoolDir, "00000000000000000007.json"), []byte(`{"seq":7}`), 0o600)
	_ = os.WriteFile(filepath.Join(f.stateDir, "agent-state.json"),
		[]byte(`{"state":"offline","last_heartbeat_ok":"2026-10-02T07:45:00Z","last_error":"Bearer `+cred.Token+`","dropped_samples":3}`), 0o600)

	if exit := f.run("status", "--json"); exit != ExitOK {
		t.Fatalf("%d %s", exit, f.output())
	}
	if strings.Contains(f.output(), cred.Token) || strings.Contains(f.output(), cred.Token[strings.IndexByte(cred.Token, '.')+1:]) {
		t.Fatal("status prints the credential secret")
	}
	var rep StatusReport
	if err := json.Unmarshal(f.stdout.Bytes(), &rep); err != nil {
		t.Fatalf("%v: %s", err, f.stdout.String())
	}
	if !rep.Paired || rep.CredentialID != cred.CredentialID || rep.DeviceID != cred.DeviceID {
		t.Fatalf("%+v", rep)
	}
	if rep.AgentState != "offline" || rep.LastHeartbeatOK != "2026-10-02T07:45:00Z" || rep.SpoolSamples != 1 || rep.SpoolBytes != 9 || rep.DroppedSamples != 3 {
		t.Fatalf("%+v", rep)
	}
	if !rep.APIReachable || !strings.Contains(rep.APIDetail, "credential accepted") {
		t.Fatalf("api: %+v", rep)
	}
	want := map[string]string{"happymining-agent": "active", "docker": "active", "vastai": "not-installed", "nvidia-persistenced": "failed"}
	for unit, state := range want {
		if rep.Services[unit] != state {
			t.Errorf("%s: %q, want %q", unit, rep.Services[unit], state)
		}
	}

	if exit := f.run("status"); exit != ExitOK {
		t.Fatal(f.output())
	}
	for _, wantText := range []string{"paired", cred.CredentialID, "2026-10-02T07:45:00Z", "1 sample(s)", "reachable", "not-installed"} {
		if !strings.Contains(f.stdout.String(), wantText) {
			t.Errorf("status lacks %q:\n%s", wantText, f.stdout.String())
		}
	}

	// Revoked on the server: the API is reachable, the credential is not accepted.
	f.api.Revoke(cred.DeviceID)
	f.run("status", "--json")
	_ = json.Unmarshal(f.stdout.Bytes(), &rep)
	if !rep.APIReachable || !strings.Contains(rep.APIDetail, "device_unauthorized") {
		t.Fatalf("revoked: %+v", rep)
	}
	// API down.
	f.srv.Close()
	f.run("status", "--json")
	rep = StatusReport{}
	_ = json.Unmarshal(f.stdout.Bytes(), &rep)
	if rep.APIReachable {
		t.Fatalf("a dead API must be reported unreachable: %+v", rep)
	}
}

func TestUnpair(t *testing.T) {
	f := newFixture(t)
	if exit := f.run("unpair", "--yes"); exit != ExitOK || !strings.Contains(f.stdout.String(), "not paired") {
		t.Fatalf("%d %s", exit, f.output())
	}
	f.run("pair", "--code", f.api.NewPairingCode())
	_ = os.MkdirAll(filepath.Join(f.stateDir, "spool"), 0o750)
	// Without confirmation nothing happens.
	f.confirm = false
	if exit := f.run("unpair"); exit != ExitFail {
		t.Fatalf("exit %d", exit)
	}
	if _, err := credential.Load(credential.Path(f.stateDir)); err != nil {
		t.Fatal("the credential was deleted without confirmation")
	}
	f.confirm = true
	if exit := f.run("unpair"); exit != ExitOK {
		t.Fatalf("%d %s", exit, f.output())
	}
	if _, err := credential.Load(credential.Path(f.stateDir)); !errors.Is(err, credential.ErrNotPaired) {
		t.Fatalf("credential still there: %v", err)
	}
	// Only the credential is removed: the identity stays.
	if _, err := os.Stat(identity.Path(f.stateDir)); err != nil {
		t.Fatal("unpair must not remove the install identity")
	}
	if !strings.Contains(f.stdout.String(), "Vast software and Docker were not touched") {
		t.Fatalf("output: %s", f.stdout.String())
	}
}

func TestPreflightCommand(t *testing.T) {
	f := newFixture(t)
	exit := f.run("preflight", "--offline")
	out := f.stdout.String()
	if exit != ExitFail { // the fixture root has no GPU
		t.Fatalf("exit %d\n%s", exit, out)
	}
	for _, want := range []string{"STATUS", "PASS", "FAIL", "Overall: FAIL", "does not guarantee", "ubuntu 24.04"} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
	if exit := f.run("preflight", "--offline", "--json"); exit != ExitFail {
		t.Fatalf("exit %d", exit)
	}
	var rep preflight.Report
	if err := json.Unmarshal(f.stdout.Bytes(), &rep); err != nil || rep.Overall != preflight.Fail || len(rep.Checks) < 15 {
		t.Fatalf("%v %+v", err, rep.Summary)
	}
	// Online: the API check talks to the configured (fake) API.
	f.run("preflight", "--json")
	_ = json.Unmarshal(f.stdout.Bytes(), &rep)
	for _, c := range rep.Checks {
		if c.ID == "network_api" && c.Status != preflight.Pass {
			t.Errorf("network_api: %+v", c)
		}
	}
	// --requirements override and its validation.
	bad := filepath.Join(t.TempDir(), "req.json")
	_ = os.WriteFile(bad, []byte(`{"schema_version":99}`), 0o644)
	if exit := f.run("preflight", "--offline", "--requirements", bad); exit != ExitUsage {
		t.Fatalf("exit %d", exit)
	}
}

func TestVastEnrollHelp(t *testing.T) {
	f := newFixture(t)
	if exit := f.run("vast-enroll-help"); exit != ExitOK {
		t.Fatalf("exit %d", exit)
	}
	out := f.stdout.String()
	for _, want := range []string{
		"does not download, embed, store or automate the Vast install command",
		"https://cloud.vast.ai/host/setup/",
		"yourself",
		"never call Vast's API",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("help lacks %q", want)
		}
	}
	// The help must not contain anything that looks like an install command.
	for _, forbidden := range []string{"wget ", "curl ", "| bash", "|bash", "| sh", "python3 install", "sudo python", "api_key", "--api-key"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("help contains %q", forbidden)
		}
	}
}

func TestUsageAndVersion(t *testing.T) {
	f := newFixture(t)
	if exit := f.run("version"); exit != ExitOK || !strings.Contains(f.stdout.String(), "happyminingctl 0.1.0") {
		t.Fatalf("%d %s", exit, f.output())
	}
	for _, args := range [][]string{{}, {"frobnicate"}, {"identity"}, {"identity", "show"}, {"pair", "extra"}, {"status", "--bogus"}} {
		if exit := f.run(args...); exit != ExitUsage {
			t.Errorf("%v: exit %d", args, exit)
		}
	}
}

func TestBrokenConfigIsAnError(t *testing.T) {
	f := newFixture(t)
	_ = os.WriteFile(f.config, []byte("HM_NOT_A_KEY=1\n"), 0o644)
	for _, args := range [][]string{{"status"}, {"pair", "--code", "x"}, {"identity", "init"}, {"unpair", "--yes"}} {
		if exit := f.run(args...); exit != ExitFail || !strings.Contains(f.stderr.String(), "unknown configuration key") {
			t.Errorf("%v: exit %d: %s", args, exit, f.output())
		}
	}
	// For preflight, exit status 1 means "a check failed" (installers rely on
	// it); a broken configuration must be distinguishable.
	if exit := f.run("preflight", "--offline"); exit != ExitUsage || !strings.Contains(f.stderr.String(), "unknown configuration key") {
		t.Errorf("preflight with a broken configuration: exit %d: %s", exit, f.output())
	}
}

func TestStateDirectoryCreatedByRootBelongsToTheAgentAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	saved := lookupAgentOwner
	defer func() { lookupAgentOwner = saved }()
	lookupAgentOwner = func() (*fsx.Owner, error) { return &fsx.Owner{UID: 54321, GID: 54322}, nil }

	f := newFixture(t) // the state directory does not exist yet
	if exit := f.run("pair", "--code", f.api.NewPairingCode()); exit != ExitOK {
		t.Fatalf("%d %s", exit, f.output())
	}
	for _, name := range []string{"", "identity", "credential.json"} {
		owner, err := fsx.OwnerOf(filepath.Join(f.stateDir, name))
		if err != nil || owner.UID != 54321 || owner.GID != 54322 {
			t.Errorf("%q is owned by %+v (%v); the unprivileged agent could not read it", name, owner, err)
		}
	}
}
