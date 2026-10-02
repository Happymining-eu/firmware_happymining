package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/applier"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/execx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/helper"
)

type testCLI struct {
	env      cliEnv
	out, err bytes.Buffer
	runner   *execx.Fake
	depsUsed bool
	served   bool
}

// newCLI builds a command-line environment whose paths are all inside a
// temporary directory and whose runner is a fake.
func newCLI(t *testing.T, euid int, conf string) *testCLI {
	t.Helper()
	root := t.TempDir()
	p := applier.Paths{
		StateDir: filepath.Join(root, "state"), PluginDataRoot: filepath.Join(root, "plugins"), NASRoot: filepath.Join(root, "srv", "nas"),
		CatalogDir: filepath.Join(root, "catalog"), BuildRoot: filepath.Join(root, "share"), ReleaseKeysDir: filepath.Join(root, "keys"),
		ProfilePath: filepath.Join(root, "etc", "appliance.json"), AgentStateDir: filepath.Join(root, "agent"),
		MountInfo: filepath.Join(root, "mountinfo"), BootID: filepath.Join(root, "boot_id"), DockerVolumes: filepath.Join(root, "volumes"),
	}
	src := filepath.Join("..", "..", "..", "appliance", "testdata", "catalog")
	_ = filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(p.CatalogDir, rel), 0o755)
		}
		data, _ := os.ReadFile(path)
		return os.WriteFile(filepath.Join(p.CatalogDir, rel), data, 0o644)
	})
	_ = os.WriteFile(p.MountInfo, []byte("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"), 0o644)
	_ = os.WriteFile(p.BootID, []byte("b1\n"), 0o644)
	confPath := filepath.Join(root, "helper.conf")
	if conf != "-" {
		_ = os.WriteFile(confPath, []byte(conf), 0o644)
	}
	c := &testCLI{runner: execx.NewFake()}
	c.env = cliEnv{
		Euid: euid, Uid: euid, Stdin: strings.NewReader(""), Stdout: &c.out, Stderr: &c.err, Audit: func(string) {},
		Deps: func(audit func(string)) helper.Deps {
			c.depsUsed = true
			return helper.Deps{ConfPath: confPath, ConfOwnerUID: uint32(os.Getuid()), Runner: c.runner, Audit: audit, Paths: p,
				AgentUID: uint32(os.Getuid()), Version: "0.2.0", HasDocker: func() bool { return true }}
		},
		Serve: func(context.Context, helper.Deps) int { c.served = true; return 0 },
	}
	return c
}

var rootOnly = [][]string{
	{"serve"}, {"restart-vast-daemon"}, {"reboot", "--delay-s", "120"},
	{"apply-stored"}, {"run-job", "backup_run"}, {"run-job", "plugin_restart-ollama"}, {"install-staged"}, {"update-guard"},
	{"appliance-status"}, {"secret-set", "nas.docs.password"}, {"backup-init"}, {"backup-restore", "--from", "/x.hmbk"},
	{"appliance-purge", "ollama"}, {"vectorizer-token"},
}

func TestRootOnlyActionsRefuseOtherUsers(t *testing.T) {
	for _, args := range rootOnly {
		c := newCLI(t, 1000, "ALLOW_PLUGINS=1\nALLOW_NAS=1\nALLOW_BACKUP=1\nALLOW_UPDATE=1\n")
		if code := run(args, c.env); code != exitNoPerm {
			t.Errorf("%q: exit %d", args, code)
		}
		if c.depsUsed || c.served || len(c.runner.CallLog()) != 0 {
			t.Errorf("%q: work was done for a non-root caller", args)
		}
	}
	c := newCLI(t, 1000, "-")
	if code := run([]string{"version"}, c.env); code != exitOK || !strings.HasPrefix(c.out.String(), "hm-helper ") {
		t.Fatal("version works for everyone")
	}
}

func TestCommandLineShapes(t *testing.T) {
	bad := [][]string{
		nil, {""}, {"shell"}, {"apply-stored", "now"}, {"run-job"}, {"run-job", "bogus"}, {"run-job", "plugin_restart-../x"},
		{"run-job", "backup_run", "x"}, {"run-job", "update_check"}, {"install-staged", "--force"}, {"secret-set"},
		{"secret-set", "--name"}, {"secret-set", "a", "b"}, {"backup-restore"}, {"backup-restore", "--to", "/x"},
		{"backup-restore", "--from", "/x", "--force", "/y"}, {"backup-restore", "--from"}, {"appliance-purge"},
		{"appliance-purge", "-rf"}, {"vectorizer-token", "x"}, {"reboot"}, {"reboot", "--delay-s", "5"}, {"serve", "x"},
	}
	for _, args := range bad {
		c := newCLI(t, 0, "-")
		if code := run(args, c.env); code != exitUsage {
			t.Errorf("%q: exit %d", args, code)
		}
		if len(c.runner.CallLog()) != 0 {
			t.Errorf("%q ran %q", args, c.runner.CallLog())
		}
	}
}

func TestCommandLineActions(t *testing.T) {
	c := newCLI(t, 0, "-")
	if code := run([]string{"vectorizer-token"}, c.env); code != exitOK || len(strings.TrimSpace(c.out.String())) < 16 {
		t.Fatalf("%d %q %q", code, c.out.String(), c.err.String())
	}
	c = newCLI(t, 0, "-")
	if code := run([]string{"appliance-status"}, c.env); code != exitOK {
		t.Fatalf("%d %s", code, c.err.String())
	}
	var res applier.StatusResult
	if err := json.Unmarshal(c.out.Bytes(), &res); err != nil || res.Reported.Control != "cloud" {
		t.Fatalf("%v %s", err, c.out.String())
	}
	c = newCLI(t, 0, "-")
	c.env.Stdin = strings.NewReader("")
	if code := run([]string{"backup-init"}, c.env); code != exitOK || !strings.Contains(c.out.String(), "hmrk1-") {
		t.Fatalf("%d %s", code, c.err.String())
	}
	if code := run([]string{"backup-init"}, c.env); code != exitRefused {
		t.Fatal("a second backup-init must be refused")
	}
	if code := run([]string{"serve"}, c.env); code != exitOK || !c.served {
		t.Fatal("serve")
	}
	// apply-stored with nothing configured: vast with nothing, no command.
	c = newCLI(t, 0, "ALLOW_PLUGINS=1\n")
	if code := run([]string{"apply-stored"}, c.env); code != exitOK {
		t.Fatalf("%d %s", code, c.err.String())
	}
	// An unusable switch file disables the heavy actions.
	c = newCLI(t, 0, "ALLOW_SHELL=1\n")
	for _, args := range [][]string{{"apply-stored"}, {"run-job", "backup_run"}, {"install-staged"}, {"update-guard"}} {
		if code := run(args, c.env); code != exitRefused {
			t.Errorf("%q: %d", args, code)
		}
	}
	if len(c.runner.CallLog()) != 0 {
		t.Fatalf("%q", c.runner.CallLog())
	}
}
