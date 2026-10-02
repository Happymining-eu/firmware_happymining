// Package packaging holds the tests of the Debian packaging tree: static
// checks of units, conffiles and maintainer scripts, a run of the maintainer
// scripts against a temporary root, and a scan of the built .deb.
package packaging

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/config"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/version"
)

// The needle is assembled so that this test file does not contain it.
var dockerSocket = "docker" + ".sock"

// textFiles returns the packaging and script files (not this test).
func textFiles(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, root := range []string{".", "../scripts"} {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out[path] = string(data)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(out) < 12 {
		t.Fatalf("only %d packaging files found", len(out))
	}
	return out
}

func TestNoDockerSocketAnywhere(t *testing.T) {
	for path, content := range textFiles(t) {
		if strings.Contains(content, dockerSocket) {
			t.Errorf("%s mentions the Docker socket", path)
		}
	}
	// The same for every non-test Go source of the agent.
	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(dockerSocket)) {
			t.Errorf("%s mentions the Docker socket", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Patterns of things that must never be packaged.
var secretPatterns = map[string]*regexp.Regexp{
	"device credential": regexp.MustCompile(`hmd_[0-9A-Za-z]{8}`),
	"pairing code":      regexp.MustCompile(`HM-[0-9A-Za-z]{6}(-[0-9A-Za-z]{4}){4}`),
	"private key":       regexp.MustCompile(`PRIVATE KEY`),
	"api key":           regexp.MustCompile(`(?i)api_key`),
}

func TestPackagingTreeHasNoSecrets(t *testing.T) {
	for path, content := range textFiles(t) {
		for name, re := range secretPatterns {
			if loc := re.FindStringIndex(content); loc != nil {
				t.Errorf("%s contains something that looks like a %s", path, name)
			}
		}
	}
}

func unit(t *testing.T, name string) map[string][]string {
	t.Helper()
	f, err := os.Open(filepath.Join("systemd", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string][]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("%s: unparseable line %q", name, line)
		}
		out[key] = append(out[key], value)
	}
	return out
}

func TestAgentUnitHardening(t *testing.T) {
	u := unit(t, "happymining-agent.service")
	want := map[string]string{
		"User":                     "happymining",
		"Group":                    "happymining",
		"ExecStart":                "/usr/bin/happymining-agent --config /etc/happymining/agent.env",
		"Restart":                  "on-failure",
		"RestartSec":               "10",
		"StartLimitIntervalSec":    "300",
		"StartLimitBurst":          "5",
		"NoNewPrivileges":          "yes",
		"ProtectSystem":            "strict",
		"ProtectHome":              "yes",
		"PrivateTmp":               "yes",
		"ProtectKernelTunables":    "yes",
		"ProtectKernelModules":     "yes",
		"ProtectControlGroups":     "yes",
		"RestrictAddressFamilies":  "AF_INET AF_INET6 AF_UNIX",
		"RestrictNamespaces":       "yes",
		"LockPersonality":          "yes",
		"MemoryDenyWriteExecute":   "yes",
		"SystemCallFilter":         "@system-service",
		"CapabilityBoundingSet":    "",
		"ReadWritePaths":           "/var/lib/happymining",
		"ProtectProc":              "invisible",
		"RestartPreventExitStatus": "78",
	}
	for key, value := range want {
		got, ok := u[key]
		if !ok || len(got) != 1 || got[0] != value {
			t.Errorf("%s: got %q, want %q", key, got, value)
		}
	}
	for _, key := range []string{"MemoryMax", "TasksMax"} {
		if len(u[key]) != 1 || u[key][0] == "" || u[key][0] == "infinity" {
			t.Errorf("%s must be set to a limit: %q", key, u[key])
		}
	}
	// GPU telemetry needs /dev/nvidia*: PrivateDevices=yes would hide them.
	if got := u["PrivateDevices"]; len(got) != 1 || got[0] != "no" {
		t.Errorf("PrivateDevices must be explicitly no: %q", got)
	}
	if _, root := u["SupplementaryGroups"]; root {
		t.Error("the agent must not get supplementary groups (for example docker)")
	}
	// Directives only (comments may explain what is deliberately absent).
	var directives []string
	for key, values := range u {
		for _, v := range values {
			directives = append(directives, key+"="+v)
		}
	}
	text := strings.Join(directives, "\n")
	for _, forbidden := range []string{"sudo", "docker", "User=root", "AmbientCapabilities=CAP", "PermissionsStartOnly", "ExecStartPre=+"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("the agent unit contains %q", forbidden)
		}
	}
}

func TestFirstbootUnit(t *testing.T) {
	u := unit(t, "happymining-firstboot.service")
	want := map[string]string{
		"Type":                "oneshot",
		"ConditionPathExists": "!/var/lib/happymining/identity",
		"ExecStart":           "/usr/bin/happyminingctl identity init",
		"User":                "happymining",
		"NoNewPrivileges":     "yes",
	}
	for key, value := range want {
		if got := u[key]; len(got) != 1 || got[0] != value {
			t.Errorf("%s: got %q, want %q", key, got, value)
		}
	}
}

func TestHelperUnits(t *testing.T) {
	sock := unit(t, "happymining-helper.socket")
	want := map[string]string{
		"ListenStream": config.DefaultHelperSocket,
		"SocketUser":   "root",
		"SocketGroup":  "happymining",
		"SocketMode":   "0660",
		"Accept":       "yes",
	}
	for key, value := range want {
		if got := sock[key]; len(got) != 1 || got[0] != value {
			t.Errorf("socket %s: got %q, want %q", key, got, value)
		}
	}
	svc := unit(t, "happymining-helper@.service")
	if got := svc["ExecStart"]; len(got) != 1 || got[0] != "/usr/lib/happymining/hm-helper serve" {
		t.Errorf("helper ExecStart: %q (the command line must be fixed)", got)
	}
	if got := svc["StandardInput"]; len(got) != 1 || got[0] != "socket" {
		t.Errorf("StandardInput: %q", got)
	}
	if got := svc["StandardError"]; len(got) != 1 || got[0] != "journal" {
		t.Errorf("StandardError must go to the journal, not to the socket: %q", got)
	}
	// The socket is not reachable from the network.
	if strings.Contains(strings.Join(sock["ListenStream"], " "), ":") {
		t.Error("the helper must not listen on a TCP port")
	}
}

func TestNoSudoersFileIsShipped(t *testing.T) {
	// The privileged path is the root socket; a sudoers rule would be a
	// second, unneeded one.
	for path, content := range textFiles(t) {
		if strings.Contains(path, "sudoers") || strings.Contains(content, "sudoers.d") || strings.Contains(content, "NOPASSWD") {
			t.Errorf("%s: sudoers content found", path)
		}
	}
}

func TestConffileDefaultsAreSafe(t *testing.T) {
	f, err := os.Open("etc/happymining/agent.env")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cfg, err := config.ParseAgent(f)
	if err != nil {
		t.Fatalf("the packaged agent.env does not parse: %v", err)
	}
	if !strings.HasPrefix(cfg.APIURL, "https://") {
		t.Errorf("API URL must be https: %q", cfg.APIURL)
	}
	if cfg.AllowInsecureLoopback || len(cfg.OpsEnabled) != 0 || cfg.CAFile != "" {
		t.Errorf("unsafe defaults: %+v", cfg)
	}
	if cfg.StateDir != config.DefaultStateDir || cfg.HeartbeatInterval != config.DefaultInterval {
		t.Errorf("unexpected defaults: %+v", cfg)
	}

	h, err := os.Open("etc/happymining/helper.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	helper, err := config.ParseHelper(h)
	if err != nil {
		t.Fatalf("the packaged helper.conf does not parse: %v", err)
	}
	if helper.AllowReboot || helper.AllowRestartVastDaemon {
		t.Fatalf("every helper switch must be off by default: %+v", helper)
	}

	conffiles, _ := os.ReadFile("debian/conffiles")
	for _, want := range []string{"/etc/happymining/agent.env", "/etc/happymining/helper.conf"} {
		if !strings.Contains(string(conffiles), want+"\n") {
			t.Errorf("%s is not declared as a conffile", want)
		}
	}
}

func TestControlFile(t *testing.T) {
	raw, err := os.ReadFile("debian/control.in")
	if err != nil {
		t.Fatal(err)
	}
	control := string(raw)
	for _, want := range []string{"Package: happymining-agent\n", "Architecture: amd64\n", "Version: @VERSION@\n", "Depends: adduser\n"} {
		if !strings.Contains(control, want) {
			t.Errorf("control lacks %q", want)
		}
	}
	for _, line := range strings.Split(control, "\n") {
		lower := strings.ToLower(line)
		for _, field := range []string{"depends:", "pre-depends:", "recommends:", "suggests:", "conflicts:", "breaks:", "replaces:"} {
			if strings.HasPrefix(lower, field) {
				for _, forbidden := range []string{"docker", "nvidia", "vast", "containerd"} {
					if strings.Contains(lower, forbidden) {
						t.Errorf("control must not relate to %s packages: %q", forbidden, line)
					}
				}
			}
		}
	}
}

func TestMaintainerScriptsNeverTouchTheHost(t *testing.T) {
	forbidden := []string{
		"apt-get", "apt ", "aptitude", "dpkg -i", "dpkg --install", "snap ", "pip ",
		"docker", "nvidia", "vastai", "kaalia",
		"parted", "sgdisk", "fdisk", "mkfs", "wipefs", "dd ", "mount ", "lvcreate", "pvcreate", "mdadm",
		"curl", "wget", "reboot", "shutdown", "poweroff", "modprobe", "happyminingctl pair",
	}
	for _, name := range []string{"postinst", "prerm", "postrm"} {
		raw, err := os.ReadFile(filepath.Join("debian", name))
		if err != nil {
			t.Fatal(err)
		}
		var code []string
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "#") {
				code = append(code, line)
			}
		}
		text := strings.Join(code, "\n")
		for _, f := range forbidden {
			if strings.Contains(text, f) {
				t.Errorf("%s contains %q", name, f)
			}
		}
		if !strings.Contains(text, "set -e") {
			t.Errorf("%s must use set -e", name)
		}
	}
}

// scriptEnv prepares a temporary root and stub commands for the maintainer
// scripts. Nothing outside the temporary directories is touched.
type scriptEnv struct {
	t     *testing.T
	root  string
	stubs string
	log   string
}

func newScriptEnv(t *testing.T, withSystemctl bool) *scriptEnv {
	t.Helper()
	e := &scriptEnv{t: t, root: t.TempDir(), stubs: t.TempDir()}
	e.log = filepath.Join(t.TempDir(), "calls.log")
	stub := func(name, body string) {
		script := "#!/bin/sh\necho \"" + name + " $*\" >>\"" + e.log + "\"\n" + body + "\n"
		if err := os.WriteFile(filepath.Join(e.stubs, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stub("getent", "exit 2") // user and group do not exist yet
	stub("addgroup", "exit 0")
	stub("adduser", "exit 0")
	stub("chown", "exit 0")
	if withSystemctl {
		// Like systemctl inside a chroot: it exists but cannot do anything.
		stub("systemctl", "exit 1")
	}
	// The scripts may only use these real tools.
	for _, tool := range []string{"sh", "mkdir", "chmod", "rm", "rmdir", "cat"} {
		path, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s not available", tool)
		}
		if err := os.Symlink(path, filepath.Join(e.stubs, tool)); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *scriptEnv) run(script string, args ...string) (string, error) {
	e.t.Helper()
	abs, err := filepath.Abs(filepath.Join("debian", script))
	if err != nil {
		e.t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(e.stubs, "sh"), append([]string{abs}, args...)...)
	// PATH holds only the stubs and the six allowed tools: anything else a
	// script tries to run fails instead of reaching the real system.
	cmd.Env = []string{"PATH=" + e.stubs, "DPKG_ROOT=" + e.root}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (e *scriptEnv) calls() string {
	data, _ := os.ReadFile(e.log)
	return string(data)
}

func TestPostinstFreshInstall(t *testing.T) {
	e := newScriptEnv(t, true)
	out, err := e.run("postinst", "configure")
	if err != nil {
		t.Fatalf("postinst must not fail when systemd cannot be used: %v\n%s", err, out)
	}
	for _, dir := range []string{"var/lib/happymining", "var/lib/happymining/spool"} {
		fi, err := os.Stat(filepath.Join(e.root, dir))
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o750 {
			t.Errorf("%s: %v %v", dir, fi, err)
		}
	}
	calls := e.calls()
	for _, want := range []string{
		"addgroup --system happymining",
		"adduser --system --ingroup happymining --no-create-home --home /nonexistent --shell /usr/sbin/nologin",
		"chown happymining:happymining " + e.root + "/var/lib/happymining",
		"systemctl enable happymining-firstboot.service happymining-helper.socket happymining-agent.service",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("expected call %q in:\n%s", want, calls)
		}
	}
	// It must not create an identity or a credential, and must not pair.
	entries, _ := os.ReadDir(filepath.Join(e.root, "var/lib/happymining"))
	if len(entries) != 1 || entries[0].Name() != "spool" {
		t.Errorf("postinst created unexpected state: %v", entries)
	}
	if strings.Contains(calls, "pair") {
		t.Errorf("postinst must never start pairing:\n%s", calls)
	}
}

func TestPostinstWithoutSystemd(t *testing.T) {
	e := newScriptEnv(t, false) // no systemctl at all (minimal chroot)
	out, err := e.run("postinst", "configure")
	if err != nil {
		t.Fatalf("postinst must not fail without systemctl: %v\n%s", err, out)
	}
	if !strings.Contains(out, "not enabled") {
		t.Errorf("the operator should be told that units were not enabled: %q", out)
	}
	if _, err := os.Stat(filepath.Join(e.root, "var/lib/happymining/spool")); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradePreservesCredentialsAndSpool(t *testing.T) {
	e := newScriptEnv(t, true)
	if out, err := e.run("postinst", "configure"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	state := filepath.Join(e.root, "var/lib/happymining")
	files := map[string]string{
		"credential.json":                 `{"fixture":"credential"}`,
		"identity":                        "fixture-identity\n",
		"seq":                             "42\n",
		"ops.journal":                     `{"id":"fixture"}` + "\n",
		"spool/00000000000000000042.json": `{"seq":42}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(state, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// dpkg's upgrade sequence: old prerm, new postinst (and old postrm upgrade).
	for _, step := range [][]string{
		{"prerm", "upgrade", "0.2.0"},
		{"postrm", "upgrade", "0.2.0"},
		{"postinst", "configure", "0.1.0"},
	} {
		if out, err := e.run(step[0], step[1:]...); err != nil {
			t.Fatalf("%v: %v\n%s", step, err, out)
		}
	}
	for name, content := range files {
		data, err := os.ReadFile(filepath.Join(state, name))
		if err != nil || string(data) != content {
			t.Errorf("%s was not preserved across the upgrade: %q %v", name, data, err)
		}
		fi, _ := os.Stat(filepath.Join(state, name))
		if fi != nil && fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode changed to %04o", name, fi.Mode().Perm())
		}
	}
}

func TestRemoveKeepsStateAndPurgeDeletesIt(t *testing.T) {
	e := newScriptEnv(t, true)
	if out, err := e.run("postinst", "configure"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	state := filepath.Join(e.root, "var/lib/happymining")
	_ = os.WriteFile(filepath.Join(state, "credential.json"), []byte("x"), 0o600)
	_ = os.MkdirAll(filepath.Join(e.root, "etc/happymining"), 0o755)
	// A neighbour that purge must never touch.
	neighbour := filepath.Join(e.root, "var/lib/vastai_kaalia")
	_ = os.MkdirAll(neighbour, 0o755)
	_ = os.WriteFile(filepath.Join(neighbour, "machine_id"), []byte("fixture"), 0o600)

	for _, step := range [][]string{{"prerm", "remove"}, {"postrm", "remove"}} {
		if out, err := e.run(step[0], step[1:]...); err != nil {
			t.Fatalf("%v: %v\n%s", step, err, out)
		}
	}
	if _, err := os.Stat(filepath.Join(state, "credential.json")); err != nil {
		t.Fatal("remove (without purge) must keep the state")
	}
	if !strings.Contains(e.calls(), "systemctl disable happymining-agent.service happymining-helper.socket happymining-firstboot.service") {
		t.Errorf("prerm remove must disable the units:\n%s", e.calls())
	}
	if out, err := e.run("postrm", "purge"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("purge must remove the state directory")
	}
	if _, err := os.Stat(filepath.Join(e.root, "etc/happymining")); !os.IsNotExist(err) {
		t.Fatal("purge should remove the empty configuration directory")
	}
	if _, err := os.Stat(filepath.Join(neighbour, "machine_id")); err != nil {
		t.Fatal("purge touched Vast's directory")
	}
	if _, err := os.Stat(filepath.Join(e.root, "var/lib")); err != nil {
		t.Fatal("purge removed too much")
	}
}

func TestScriptsRejectUnknownArguments(t *testing.T) {
	e := newScriptEnv(t, true)
	for _, script := range []string{"postinst", "prerm", "postrm"} {
		if _, err := e.run(script, "frobnicate"); err == nil {
			t.Errorf("%s accepted an unknown argument", script)
		}
	}
}

func TestBuildScriptsUseTheVersionConstant(t *testing.T) {
	raw, err := os.ReadFile("../internal/version/version.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^var Version = "(.*)"$`).FindSubmatch(raw)
	if m == nil || string(m[1]) != version.Version {
		t.Fatalf("build scripts read the version with a pattern that no longer matches version.go")
	}
	if version.Version != "0.1.0" {
		t.Fatalf("version is %q", version.Version)
	}
	for _, script := range []string{"../scripts/build.sh", "../scripts/build-deb.sh"} {
		data, _ := os.ReadFile(script)
		for _, want := range []string{"internal/version/version.go"} {
			if !strings.Contains(string(data), want) {
				t.Errorf("%s does not read the version from the single source of truth", script)
			}
		}
		if regexp.MustCompile(`0\.1\.0`).Match(data) {
			t.Errorf("%s hard-codes the version", script)
		}
	}
	build, _ := os.ReadFile("../scripts/build.sh")
	for _, want := range []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "-trimpath", "-buildvcs=false", "-s -w", "SOURCE_DATE_EPOCH", "internal/version.Version="} {
		if !strings.Contains(string(build), want) {
			t.Errorf("build.sh lacks %q", want)
		}
	}
}

func TestSourcesNeverDisableTLSVerification(t *testing.T) {
	needle := "Insecure" + "SkipVerify"
	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(needle)) {
			t.Errorf("%s can disable TLS certificate verification", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// debPath returns the built package, or "" if it was not built.
func debPath(t *testing.T) string {
	t.Helper()
	dist := os.Getenv("HM_DIST_DIR")
	if dist == "" {
		dist = filepath.Join("..", "..", "dist")
	}
	path := filepath.Join(dist, "happymining-agent_"+version.Version+"_amd64.deb")
	if _, err := os.Stat(path); err != nil {
		if os.Getenv("HM_REQUIRE_DEB") != "" {
			t.Fatalf("HM_REQUIRE_DEB is set but %s does not exist: run scripts/build-deb.sh", path)
		}
		t.Skipf("%s not built (run scripts/build-deb.sh); skipping the package scan", path)
	}
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		t.Skip("dpkg-deb not available")
	}
	return path
}

func TestDebContentsHaveNoSecretsAndNoDockerSocket(t *testing.T) {
	deb := debPath(t)
	dir := t.TempDir()
	if out, err := exec.Command("dpkg-deb", "--raw-extract", deb, dir).CombinedOutput(); err != nil {
		t.Fatalf("dpkg-deb --raw-extract: %v\n%s", err, out)
	}
	files := 0
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		files++
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(path, dir)
		for name, re := range secretPatterns {
			if loc := re.FindIndex(data); loc != nil {
				t.Errorf("%s contains something that looks like a %s", rel, name)
			}
		}
		if bytes.Contains(data, []byte(dockerSocket)) {
			t.Errorf("%s mentions the Docker socket", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 14 {
		t.Fatalf("only %d files in the package", files)
	}
	// State that must only ever be created on the machine itself.
	for _, forbidden := range []string{"var/lib/happymining", "etc/sudoers.d", "root/.ssh", "etc/ssh"} {
		if _, err := os.Stat(filepath.Join(dir, forbidden)); err == nil {
			t.Errorf("the package ships %s", forbidden)
		}
	}
}

func TestDebLayoutOwnersAndModes(t *testing.T) {
	deb := debPath(t)
	out, err := exec.Command("dpkg-deb", "--contents", deb).CombinedOutput()
	if err != nil {
		t.Fatalf("dpkg-deb --contents: %v\n%s", err, out)
	}
	modes := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			t.Fatalf("unexpected line %q", line)
		}
		if fields[1] != "root/root" {
			t.Errorf("%s is owned by %s, want root/root", fields[5], fields[1])
		}
		modes[strings.TrimPrefix(fields[5], ".")] = fields[0]
	}
	want := map[string]string{
		"/usr/bin/happymining-agent":                        "-rwxr-xr-x",
		"/usr/bin/happyminingctl":                           "-rwxr-xr-x",
		"/usr/lib/happymining/hm-helper":                    "-rwxr-xr-x",
		"/lib/systemd/system/happymining-agent.service":     "-rw-r--r--",
		"/lib/systemd/system/happymining-firstboot.service": "-rw-r--r--",
		"/lib/systemd/system/happymining-helper.socket":     "-rw-r--r--",
		"/lib/systemd/system/happymining-helper@.service":   "-rw-r--r--",
		"/etc/happymining/agent.env":                        "-rw-r--r--",
		"/etc/happymining/helper.conf":                      "-rw-r--r--",
		"/etc/update-motd.d/60-happymining":                 "-rwxr-xr-x",
		"/etc/issue.d/happymining.issue":                    "-rw-r--r--",
		"/usr/share/doc/happymining-agent/README.md":        "-rw-r--r--",
	}
	for path, mode := range want {
		if modes[path] != mode {
			t.Errorf("%s: mode %q, want %q", path, modes[path], mode)
		}
	}
	for path, mode := range modes {
		// Nothing setuid, setgid or world-writable.
		if strings.ContainsAny(mode, "sStT") || (len(mode) == 10 && mode[8] == 'w') {
			t.Errorf("%s has mode %s", path, mode)
		}
		if strings.Contains(path, "hm-simulator") || strings.Contains(path, "fakeapi") {
			t.Errorf("test tooling is packaged: %s", path)
		}
	}

	info, err := exec.Command("dpkg-deb", "--field", deb).CombinedOutput()
	if err != nil {
		t.Fatalf("dpkg-deb --field: %v\n%s", err, info)
	}
	fields := string(info)
	for _, wantField := range []string{"Package: happymining-agent\n", "Version: " + version.Version + "\n", "Architecture: amd64\n", "Depends: adduser\n"} {
		if !strings.Contains(fields, wantField) {
			t.Errorf("control lacks %q:\n%s", wantField, fields)
		}
	}
	lower := strings.ToLower(fields)
	for _, line := range strings.Split(lower, "\n") {
		if strings.HasPrefix(line, "depends:") || strings.HasPrefix(line, "pre-depends:") || strings.HasPrefix(line, "recommends:") {
			if strings.Contains(line, "docker") || strings.Contains(line, "nvidia") {
				t.Errorf("forbidden dependency: %s", line)
			}
		}
	}

	conffiles, err := exec.Command("dpkg-deb", "--ctrl-tarfile", deb).Output()
	if err != nil || !bytes.Contains(conffiles, []byte("conffiles")) {
		t.Errorf("the package has no conffiles member: %v", err)
	}
}

func TestDebBinariesReportTheVersion(t *testing.T) {
	deb := debPath(t)
	dir := t.TempDir()
	if out, err := exec.Command("dpkg-deb", "--extract", deb, dir).CombinedOutput(); err != nil {
		t.Fatalf("dpkg-deb --extract: %v\n%s", err, out)
	}
	for bin, args := range map[string][]string{
		"usr/bin/happymining-agent":     {"--version"},
		"usr/bin/happyminingctl":        {"version"},
		"usr/lib/happymining/hm-helper": {"version"},
	} {
		out, err := exec.Command(filepath.Join(dir, bin), args...).CombinedOutput()
		if err != nil || !strings.Contains(string(out), version.Version) {
			t.Errorf("%s: %v %q", bin, err, out)
		}
	}
	// The packaged helper refuses a command line it does not know (as root:
	// usage error; as anyone else: it refuses to run at all).
	cmd := exec.Command(filepath.Join(dir, "usr/lib/happymining/hm-helper"), "sh", "-c", "id")
	cmd.Env = []string{"JOURNAL_STREAM=0:0"} // audit line goes to stderr, not to this machine's syslog
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("the helper accepted an unknown command line: %s", out)
	}
	if strings.Contains(string(out), "uid=") {
		t.Fatalf("the helper executed an arbitrary command: %s", out)
	}
}
