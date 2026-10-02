package applier

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
)

type testRelease struct {
	version, min string
	artifact     []byte
	manifest     []byte
	signature    string
	filename     string
}

type updateHarness struct {
	*harness
	priv ed25519.PrivateKey
}

func newUpdateHarness(t *testing.T) *updateHarness {
	h := newHarness(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	h.writeFile(filepath.Join(h.env.Paths.ReleaseKeysDir, "test.pub"), base64.StdEncoding.EncodeToString(pub)+"\n", 0o644)
	if err := os.Chmod(h.env.Paths.ReleaseKeysDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := h.env.ensureStateDir(); err != nil {
		t.Fatal(err)
	}
	h.writeFile(filepath.Join(h.env.Paths.packagesDir(), currentDeb), "the installed package 0.2.0", 0o600)
	if err := os.MkdirAll(h.env.Paths.agentDownloadDir(), 0o750); err != nil {
		t.Fatal(err)
	}
	return &updateHarness{harness: h, priv: priv}
}

func (u *updateHarness) release(version, min string, artifact []byte) testRelease {
	sum := sha256.Sum256(artifact)
	r := testRelease{version: version, min: min, artifact: artifact, filename: "happymining-agent_" + version + "_amd64.deb"}
	r.manifest = []byte(fmt.Sprintf(`{"schema":1,"product":"happymining-agent","version":%q,"created_at":"2026-10-02T12:00:00Z",`+
		`"artifact":{"filename":%q,"size":%d,"sha256":%q},"min_upgrade_from":%q,"notes":"test"}`,
		version, r.filename, len(artifact), hex.EncodeToString(sum[:]), min))
	r.signature = base64.StdEncoding.EncodeToString(ed25519.Sign(u.priv, r.manifest))
	return r
}

// download places the artifact where the agent downloads it.
func (u *updateHarness) download(r testRelease) string {
	path := filepath.Join(u.env.Paths.agentDownloadDir(), r.filename)
	u.writeFile(path, string(r.artifact), 0o600)
	return path
}

func (u *updateHarness) request(r testRelease, path string) UpdateRequest {
	return UpdateRequest{Version: r.version, ManifestB64: base64.StdEncoding.EncodeToString(r.manifest), SignatureB64: r.signature, ArtifactPath: path}
}

func TestQuickUpdateInstallStagesAndStarts(t *testing.T) {
	u := newUpdateHarness(t)
	r := u.release("0.3.0", "0.1.0", []byte("new package bytes"))
	out := QuickUpdateInstall(context.Background(), u.env, u.request(r, u.download(r)))
	if !out.OK {
		t.Fatalf("%+v", out)
	}
	if !reflect.DeepEqual(u.sys.lines(), []string{SystemctlPath + " start --no-block " + UnitUpdateInstall}) {
		t.Fatalf("%q", u.sys.lines())
	}
	staged := filepath.Join(u.env.Paths.stagingDir(), r.filename)
	if b, err := os.ReadFile(staged); err != nil || string(b) != "new package bytes" || mode(t, staged) != 0o600 {
		t.Fatalf("%q %v", b, err)
	}
	st := u.state()
	if st.Update.State != appliance.UpdateInstalling || st.Update.TargetVersion != "0.3.0" || st.Update.FromVersion != "0.2.0" {
		t.Fatalf("%+v", st.Update)
	}
}

func TestQuickUpdateInstallRefusals(t *testing.T) {
	type tc struct {
		prepare func(u *updateHarness) UpdateRequest
		code    string
		want    string
	}
	good := func(u *updateHarness) (testRelease, UpdateRequest) {
		r := u.release("0.3.0", "0.1.0", []byte("new package bytes"))
		return r, u.request(r, u.download(r))
	}
	cases := map[string]tc{
		"switch off": {func(u *updateHarness) UpdateRequest {
			u.env.Switches.AllowUpdate = false
			_, req := good(u)
			return req
		}, CodeDisabled, "ALLOW_UPDATE"},
		"bad signature": {func(u *updateHarness) UpdateRequest {
			_, req := good(u)
			other, _, _ := ed25519.GenerateKey(nil)
			_ = other
			sig, _ := base64.StdEncoding.DecodeString(req.SignatureB64)
			sig[0] ^= 1
			req.SignatureB64 = base64.StdEncoding.EncodeToString(sig)
			return req
		}, CodeInvalid, "signature"},
		"altered manifest": {func(u *updateHarness) UpdateRequest {
			r, req := good(u)
			req.ManifestB64 = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(r.manifest), `"notes":"test"`, `"notes":"tesT"`, 1)))
			return req
		}, CodeInvalid, "signature"},
		"no keys": {func(u *updateHarness) UpdateRequest {
			_ = os.Remove(filepath.Join(u.env.Paths.ReleaseKeysDir, "test.pub"))
			_, req := good(u)
			return req
		}, CodeInvalid, "no release public key"},
		"key directory writable by others": {func(u *updateHarness) UpdateRequest {
			_ = os.Chmod(u.env.Paths.ReleaseKeysDir, 0o777)
			_, req := good(u)
			return req
		}, CodeInvalid, "release keys"},
		"version mismatch": {func(u *updateHarness) UpdateRequest {
			_, req := good(u)
			req.Version = "0.4.0"
			return req
		}, CodeInvalid, "not 0.4.0"},
		"downgrade": {func(u *updateHarness) UpdateRequest {
			r := u.release("0.1.9", "0.0.0", []byte("old"))
			return u.request(r, u.download(r))
		}, CodeInvalid, "cannot be installed over"},
		"reinstall": {func(u *updateHarness) UpdateRequest {
			r := u.release("0.2.0", "0.0.0", []byte("same"))
			return u.request(r, u.download(r))
		}, CodeInvalid, "cannot be installed over"},
		"min_upgrade_from": {func(u *updateHarness) UpdateRequest {
			r := u.release("0.3.0", "0.2.1", []byte("needs newer"))
			return u.request(r, u.download(r))
		}, CodeInvalid, "cannot be installed over"},
		"artifact outside the download directory": {func(u *updateHarness) UpdateRequest {
			r, req := good(u)
			other := filepath.Join(u.root, "tmp", r.filename)
			u.writeFile(other, string(r.artifact), 0o600)
			req.ArtifactPath = other
			return req
		}, CodeInvalid, "not directly inside"},
		"artifact in a subdirectory": {func(u *updateHarness) UpdateRequest {
			r, req := good(u)
			sub := filepath.Join(u.env.Paths.agentDownloadDir(), "x", r.filename)
			u.writeFile(sub, string(r.artifact), 0o600)
			req.ArtifactPath = sub
			return req
		}, CodeInvalid, "not directly inside"},
		"dot-dot path": {func(u *updateHarness) UpdateRequest {
			r, req := good(u)
			req.ArtifactPath = u.env.Paths.agentDownloadDir() + "/../updates/" + r.filename
			return req
		}, CodeInvalid, "not directly inside"},
		"other name": {func(u *updateHarness) UpdateRequest {
			r, req := good(u)
			p := filepath.Join(u.env.Paths.agentDownloadDir(), "other.deb")
			u.writeFile(p, string(r.artifact), 0o600)
			req.ArtifactPath = p
			return req
		}, CodeInvalid, "file name"},
		"symbolic link": {func(u *updateHarness) UpdateRequest {
			r, req := good(u)
			real := filepath.Join(u.root, "real.deb")
			u.writeFile(real, string(r.artifact), 0o600)
			_ = os.Remove(req.ArtifactPath)
			_ = os.Symlink(real, req.ArtifactPath)
			return req
		}, CodeInvalid, "symbolic link"},
		"download directory is a link": {func(u *updateHarness) UpdateRequest {
			r, req := good(u)
			dir := u.env.Paths.agentDownloadDir()
			elsewhere := filepath.Join(u.root, "elsewhere")
			_ = os.MkdirAll(elsewhere, 0o750)
			u.writeFile(filepath.Join(elsewhere, r.filename), string(r.artifact), 0o600)
			_ = os.RemoveAll(dir)
			_ = os.Symlink(elsewhere, dir)
			return req
		}, CodeInvalid, "symbolic link"},
		"wrong owner": {func(u *updateHarness) UpdateRequest {
			u.env.AgentUID = u.env.AgentUID + 1
			_, req := good(u)
			return req
		}, CodeInvalid, "owned by the agent"},
		"wrong size": {func(u *updateHarness) UpdateRequest {
			r, req := good(u)
			u.writeFile(req.ArtifactPath, string(r.artifact)+"x", 0o600)
			return req
		}, CodeInvalid, "size"},
		"wrong hash": {func(u *updateHarness) UpdateRequest {
			r, req := good(u)
			u.writeFile(req.ArtifactPath, strings.ToUpper(string(r.artifact)), 0o600)
			return req
		}, CodeInvalid, "does not match the manifest"},
		"no rollback package": {func(u *updateHarness) UpdateRequest {
			_ = os.Remove(filepath.Join(u.env.Paths.packagesDir(), currentDeb))
			_, req := good(u)
			return req
		}, CodeFailed, "ALLOW_UPDATE_WITHOUT_ROLLBACK"},
		"rolled back before": {func(u *updateHarness) UpdateRequest {
			u.env.updateState(func(st *State) { st.Update.RolledBackVersion = "0.3.0" })
			_, req := good(u)
			return req
		}, CodeInvalid, "rolled back"},
		"busy": {func(u *updateHarness) UpdateRequest {
			l, err := takeLock(u.env.Paths.state(updateLockFile))
			if err != nil {
				u.t.Fatal(err)
			}
			u.t.Cleanup(l.release)
			_, req := good(u)
			return req
		}, CodeBusy, "in progress"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			u := newUpdateHarness(t)
			req := c.prepare(u)
			u.sys.reset()
			out := QuickUpdateInstall(context.Background(), u.env, req)
			if out.OK || out.Code != c.code || !strings.Contains(out.Detail, c.want) {
				t.Fatalf("%+v", out)
			}
			if len(u.sys.lines()) != 0 {
				t.Fatalf("%q", u.sys.lines())
			}
			entries, _ := os.ReadDir(u.env.Paths.stagingDir())
			if len(entries) != 0 {
				t.Fatalf("something was staged: %v", entries)
			}
		})
	}
	t.Run("without rollback when allowed", func(t *testing.T) {
		u := newUpdateHarness(t)
		u.env.Switches.AllowUpdateWithoutRollback = true
		_ = os.Remove(filepath.Join(u.env.Paths.packagesDir(), currentDeb))
		r := u.release("0.3.0", "0.1.0", []byte("x"))
		if out := QuickUpdateInstall(context.Background(), u.env, u.request(r, u.download(r))); !out.OK {
			t.Fatalf("%+v", out)
		}
	})
}

func stageForInstall(t *testing.T, u *updateHarness) testRelease {
	r := u.release("0.3.0", "0.1.0", []byte("new package bytes"))
	if out := QuickUpdateInstall(context.Background(), u.env, u.request(r, u.download(r))); !out.OK {
		t.Fatalf("%+v", out)
	}
	u.sys.reset()
	return r
}

// A machine installed from the image has no packages/current.deb yet; the
// installer left the package it installed in /var/cache/happymining. That copy
// becomes the rollback package, but only when it is the installed version,
// root's, unaltered and matches its checksum.
func TestTheInstallersPackageBecomesTheRollbackPackage(t *testing.T) {
	installed := []byte("the package the image installed")
	sum := sha256.Sum256(installed)
	name := "happymining-agent_0.2.0_amd64.deb" // the harness runs version 0.2.0
	setup := func(t *testing.T, change func(u *updateHarness, cache string)) (*updateHarness, Outcome) {
		u := newUpdateHarness(t)
		_ = os.Remove(filepath.Join(u.env.Paths.packagesDir(), currentDeb))
		cache := u.env.Paths.InstallerCache
		u.writeFile(filepath.Join(cache, name), string(installed), 0o644)
		u.writeFile(filepath.Join(cache, name+".sha256"), hex.EncodeToString(sum[:])+"  "+name+"\n", 0o644)
		u.writeFile(filepath.Join(cache, "current"), name+"\n", 0o644)
		if change != nil {
			change(u, cache)
		}
		r := u.release("0.3.0", "0.1.0", []byte("new package bytes"))
		return u, QuickUpdateInstall(context.Background(), u.env, u.request(r, u.download(r)))
	}

	u, out := setup(t, nil)
	if !out.OK {
		t.Fatalf("refused: %+v", out)
	}
	if b, err := os.ReadFile(filepath.Join(u.env.Paths.packagesDir(), currentDeb)); err != nil || string(b) != string(installed) {
		t.Fatalf("current.deb %q %v", b, err)
	}
	if mode(t, filepath.Join(u.env.Paths.packagesDir(), currentDeb)) != 0o600 {
		t.Fatal("current.deb mode")
	}

	for label, change := range map[string]func(u *updateHarness, cache string){
		"another version": func(u *updateHarness, cache string) {
			other := "happymining-agent_0.1.0_amd64.deb"
			u.writeFile(filepath.Join(cache, other), string(installed), 0o644)
			u.writeFile(filepath.Join(cache, other+".sha256"), hex.EncodeToString(sum[:])+"  "+other+"\n", 0o644)
			u.writeFile(filepath.Join(cache, "current"), other+"\n", 0o644)
		},
		"altered package": func(u *updateHarness, cache string) {
			u.writeFile(filepath.Join(cache, name), "something else", 0o644)
		},
		"checksum of another file": func(u *updateHarness, cache string) {
			u.writeFile(filepath.Join(cache, name+".sha256"), hex.EncodeToString(sum[:])+"  other.deb\n", 0o644)
		},
		"package writable by others": func(u *updateHarness, cache string) {
			u.writeFile(filepath.Join(cache, name), string(installed), 0o666)
		},
		"package is a link": func(u *updateHarness, cache string) {
			target := filepath.Join(u.root, "elsewhere.deb")
			u.writeFile(target, string(installed), 0o644)
			_ = os.Remove(filepath.Join(cache, name))
			if err := os.Symlink(target, filepath.Join(cache, name)); err != nil {
				t.Fatal(err)
			}
		},
		"name with a path": func(u *updateHarness, cache string) {
			u.writeFile(filepath.Join(cache, "current"), "../"+name+"\n", 0o644)
		},
		"no cache": func(u *updateHarness, cache string) {
			_ = os.RemoveAll(cache)
		},
	} {
		t.Run(label, func(t *testing.T) {
			u, out := setup(t, change)
			if out.OK || !strings.Contains(out.Detail, "ALLOW_UPDATE_WITHOUT_ROLLBACK") {
				t.Fatalf("not refused: %+v", out)
			}
			if regularFileExists(filepath.Join(u.env.Paths.packagesDir(), currentDeb)) {
				t.Fatal("current.deb was created")
			}
		})
	}
}

func TestInstallStaged(t *testing.T) {
	u := newUpdateHarness(t)
	r := stageForInstall(t, u)
	p := u.env.Paths
	if err := InstallStaged(context.Background(), u.env); err != nil {
		t.Fatal(err)
	}
	want := []string{
		DpkgPath + " --force-confdef --force-confold -i " + filepath.Join(p.stagingDir(), r.filename),
		SystemctlPath + " restart " + UnitUpdateGuardTimer,
	}
	if !reflect.DeepEqual(u.sys.lines(), want) {
		t.Fatalf("%q", u.sys.lines())
	}
	if b, _ := os.ReadFile(filepath.Join(p.packagesDir(), previousDeb)); string(b) != "the installed package 0.2.0" {
		t.Fatalf("previous %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(p.packagesDir(), currentDeb)); string(b) != "new package bytes" {
		t.Fatalf("current %q", b)
	}
	st := u.state()
	if st.Update.State != appliance.UpdateInstalled || st.Update.InstalledAt == "" || st.Update.InstallStartedAt == "" || st.Update.GuardDone {
		t.Fatalf("%+v", st.Update)
	}
	if entries, _ := os.ReadDir(p.stagingDir()); len(entries) != 0 {
		t.Fatalf("staging not cleared: %v", entries)
	}
	// Nothing staged: nothing happens.
	u.sys.reset()
	if err := InstallStaged(context.Background(), u.env); err != nil || len(u.sys.lines()) != 0 {
		t.Fatalf("%v %q", err, u.sys.lines())
	}
}

func TestInstallStagedFailureReinstallsPrevious(t *testing.T) {
	u := newUpdateHarness(t)
	r := stageForInstall(t, u)
	p := u.env.Paths
	u.sys.override = func(argv []string) (fakeResp, bool) {
		if strings.Join(argv, " ") == DpkgPath+" --force-confdef --force-confold -i "+filepath.Join(p.stagingDir(), r.filename) {
			return fakeResp{code: 1, stderr: "dpkg: error processing archive"}, true
		}
		return fakeResp{}, false
	}
	if err := InstallStaged(context.Background(), u.env); err == nil {
		t.Fatal("must fail")
	}
	if !reflect.DeepEqual(u.sys.lines()[1:], []string{DpkgPath + " --force-confdef --force-confold -i " + filepath.Join(p.packagesDir(), previousDeb)}) {
		t.Fatalf("%q", u.sys.lines())
	}
	st := u.state()
	if st.Update.State != appliance.UpdateError || !strings.Contains(st.Update.Detail, "previous package was installed again") {
		t.Fatalf("%+v", st.Update)
	}
	if b, _ := os.ReadFile(filepath.Join(p.packagesDir(), currentDeb)); string(b) != "the installed package 0.2.0" {
		t.Fatalf("current.deb must still be the installed package: %q", b)
	}
}

func TestInstallStagedReverifies(t *testing.T) {
	for name, tamper := range map[string]func(u *updateHarness, r testRelease){
		"package changed after staging": func(u *updateHarness, r testRelease) {
			u.writeFile(filepath.Join(u.env.Paths.stagingDir(), r.filename), "evil package byte", 0o600)
		},
		"staged record changed": func(u *updateHarness, r testRelease) {
			path := filepath.Join(u.env.Paths.stagingDir(), stagedFile)
			b, _ := os.ReadFile(path)
			u.writeFile(path, strings.Replace(string(b), r.signature, base64.StdEncoding.EncodeToString(make([]byte, 64)), 1), 0o600)
		},
		"key removed since": func(u *updateHarness, r testRelease) {
			_ = os.Remove(filepath.Join(u.env.Paths.ReleaseKeysDir, "test.pub"))
		},
		"switch turned off": func(u *updateHarness, r testRelease) { u.env.Switches.AllowUpdate = false },
		"current package vanished": func(u *updateHarness, r testRelease) {
			_ = os.Remove(filepath.Join(u.env.Paths.packagesDir(), currentDeb))
		},
		"newer version installed meanwhile": func(u *updateHarness, r testRelease) { u.env.Version = "0.3.0" },
	} {
		t.Run(name, func(t *testing.T) {
			u := newUpdateHarness(t)
			r := stageForInstall(t, u)
			tamper(u, r)
			if err := InstallStaged(context.Background(), u.env); err == nil {
				t.Fatal("must be refused")
			}
			if count(u.sys.lines(), DpkgPath) != 0 {
				t.Fatalf("dpkg ran: %q", u.sys.lines())
			}
			if st := u.state(); st.Update.State != appliance.UpdateError {
				t.Fatalf("%+v", st.Update)
			}
		})
	}
}

func TestUpdateGuard(t *testing.T) {
	install := func(t *testing.T) *updateHarness {
		u := newUpdateHarness(t)
		stageForInstall(t, u)
		if err := InstallStaged(context.Background(), u.env); err != nil {
			t.Fatal(err)
		}
		u.sys.reset()
		return u
	}
	t.Run("heartbeat of the new version", func(t *testing.T) {
		u := install(t)
		u.setAgentState("m", u.now.Add(time.Minute).Format(time.RFC3339), "0.3.0")
		if err := UpdateGuard(context.Background(), u.env); err != nil {
			t.Fatal(err)
		}
		if len(u.sys.lines()) != 0 {
			t.Fatalf("%q", u.sys.lines())
		}
		if st := u.state(); st.Update.State != appliance.UpdateInstalled || !st.Update.GuardDone {
			t.Fatalf("%+v", st.Update)
		}
	})
	for name, agent := range map[string][2]string{
		"no heartbeat":             {"", "0.3.0"},
		"heartbeat before install": {"2026-10-02T11:00:00Z", "0.3.0"},
		"heartbeat of old version": {"2026-10-02T12:05:00Z", "0.2.0"},
	} {
		t.Run(name, func(t *testing.T) {
			u := install(t)
			u.setAgentState("m", agent[0], agent[1])
			if err := UpdateGuard(context.Background(), u.env); err != nil {
				t.Fatal(err)
			}
			p := u.env.Paths
			if !reflect.DeepEqual(u.sys.lines(), []string{DpkgPath + " --force-confdef --force-confold -i " + filepath.Join(p.packagesDir(), previousDeb)}) {
				t.Fatalf("%q", u.sys.lines())
			}
			st := u.state()
			if st.Update.State != appliance.UpdateRolledBack || st.Update.RolledBackVersion != "0.3.0" || !st.Update.GuardDone {
				t.Fatalf("%+v", st.Update)
			}
			if b, _ := os.ReadFile(filepath.Join(p.packagesDir(), currentDeb)); string(b) != "the installed package 0.2.0" {
				t.Fatalf("%q", b)
			}
			// Decided: the guard does nothing more.
			u.sys.reset()
			_ = UpdateGuard(context.Background(), u.env)
			if len(u.sys.lines()) != 0 {
				t.Fatal("the guard acted twice")
			}
		})
	}
	t.Run("no previous package", func(t *testing.T) {
		u := install(t)
		_ = os.Remove(filepath.Join(u.env.Paths.packagesDir(), previousDeb))
		if err := UpdateGuard(context.Background(), u.env); err == nil {
			t.Fatal("must report")
		}
		if count(u.sys.lines(), DpkgPath) != 0 {
			t.Fatal("nothing else is ever installed")
		}
		if st := u.state(); st.Update.State != appliance.UpdateError || !st.Update.GuardDone {
			t.Fatalf("%+v", st.Update)
		}
	})
	t.Run("nothing installed", func(t *testing.T) {
		u := newUpdateHarness(t)
		if err := UpdateGuard(context.Background(), u.env); err != nil || len(u.sys.lines()) != 0 {
			t.Fatalf("%v %q", err, u.sys.lines())
		}
	})
	t.Run("status starts the guard after a reboot", func(t *testing.T) {
		u := install(t)
		u.now = u.now.Add(15 * time.Minute)
		if _, err := Status(context.Background(), u.env); err != nil {
			t.Fatal(err)
		}
		if !u.sys.started(UnitUpdateGuard) {
			t.Fatalf("%q", u.sys.lines())
		}
	})
}
