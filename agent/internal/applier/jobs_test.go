package applier

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/backup"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/config"
)

func TestJobInstances(t *testing.T) {
	for _, c := range []struct{ job, plugin, want string }{
		{JobVectorizeSync, "", "vectorize_sync"}, {JobBackupRun, "", "backup_run"}, {JobStatusRefresh, "", "status_refresh"},
		{JobPluginRestart, "ollama", "plugin_restart-ollama"}, {JobPluginRestart, "open-webui", "plugin_restart-open-webui"},
	} {
		got, err := JobInstance(c.job, c.plugin)
		if err != nil || got != c.want {
			t.Errorf("%s %s: %q %v", c.job, c.plugin, got, err)
		}
		job, plugin, err := ParseJobInstance(got)
		if err != nil || job != c.job || plugin != c.plugin {
			t.Errorf("parse %s: %s %s %v", got, job, plugin, err)
		}
		if JobUnit(got) != "happymining-appliance-job@"+c.want+".service" {
			t.Error(JobUnit(got))
		}
	}
	for _, bad := range [][2]string{{JobPluginRestart, ""}, {JobPluginRestart, "../x"}, {JobPluginRestart, "a;b"},
		{JobVectorizeSync, "x"}, {"update_check", ""}, {"rm", ""}} {
		if _, err := JobInstance(bad[0], bad[1]); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	for _, bad := range []string{"", "plugin_restart-", "plugin_restart-A", "plugin_restart-x/y", "plugin_restart", "backup_run;x",
		"vectorize_sync ", "update_check", "plugin_restart--x"} {
		if _, _, err := ParseJobInstance(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestQuickRunJob(t *testing.T) {
	h := newHarness(t)
	h.mustApply(pluginsDoc(1, plug("qdrant", true, nil)))
	h.sys.reset()
	for _, c := range []struct {
		job, plugin string
		sw          func(*config.Helper)
		code        string
		unit        string
	}{
		{JobVectorizeSync, "", nil, "", "happymining-appliance-job@vectorize_sync.service"},
		{JobBackupRun, "", nil, "", "happymining-appliance-job@backup_run.service"},
		{JobPluginRestart, "qdrant", nil, "", "happymining-appliance-job@plugin_restart-qdrant.service"},
		{JobPluginRestart, "ollama", nil, CodeInvalid, ""},
		{JobPluginRestart, "../x", nil, CodeInvalid, ""},
		{JobStatusRefresh, "", nil, CodeInvalid, ""},
		{"update_check", "", nil, CodeInvalid, ""},
		{JobVectorizeSync, "", func(s *config.Helper) { s.AllowPlugins = false }, CodeDisabled, ""},
		{JobPluginRestart, "qdrant", func(s *config.Helper) { s.AllowPlugins = false }, CodeDisabled, ""},
		{JobBackupRun, "", func(s *config.Helper) { s.AllowBackup = false }, CodeDisabled, ""},
	} {
		h.env.Switches = allOn()
		if c.sw != nil {
			c.sw(&h.env.Switches)
		}
		h.sys.reset()
		out := QuickRunJob(context.Background(), h.env, c.job, c.plugin)
		if c.code == "" {
			if !out.OK || !reflect.DeepEqual(h.sys.lines(), []string{SystemctlPath + " start --no-block " + c.unit}) {
				t.Errorf("%s %s: %+v %q", c.job, c.plugin, out, h.sys.lines())
			}
			continue
		}
		if out.OK || out.Code != c.code || len(h.sys.lines()) != 0 {
			t.Errorf("%s %s: %+v %q", c.job, c.plugin, out, h.sys.lines())
		}
	}
}

func TestRunJobVectorizeSyncAndRestart(t *testing.T) {
	h := newHarness(t)
	h.env.Switches.AllowUnpinnedImages = true
	h.env.Switches.AllowForeignContainers = true
	// No vectorizer configured: skipped.
	h.mustApply(pluginsDoc(1, plug("qdrant", true, nil)))
	if err := RunJob(context.Background(), h.env, "vectorize_sync"); err != nil {
		t.Fatal(err)
	}
	if j := h.state().job("vectorize_sync"); j.LastStatus != appliance.RunSkipped {
		t.Fatalf("%+v", j)
	}
	h.mustApply(fullDoc(h, 2))
	sync := DockerPath + " compose -p hm-vectorizer exec -T vectorizer /opt/venv/bin/python -m hm_vectorizer sync"
	for _, c := range []struct {
		code   int
		status string
	}{{0, appliance.RunOK}, {3, appliance.RunSkipped}, {1, appliance.RunFailed}} {
		h.sys.reset()
		code := c.code
		h.sys.override = func(argv []string) (fakeResp, bool) {
			if strings.Join(argv, " ") == sync {
				return fakeResp{code: code, stderr: "boom"}, true
			}
			return fakeResp{}, false
		}
		err := RunJob(context.Background(), h.env, "vectorize_sync")
		if (err != nil) != (c.status == appliance.RunFailed) {
			t.Fatalf("exit %d: %v", c.code, err)
		}
		if index(h.sys.lines(), sync) < 0 {
			t.Fatalf("%q", h.sys.lines())
		}
		if j := h.state().job("vectorize_sync"); j.LastStatus != c.status {
			t.Fatalf("exit %d: %+v", c.code, j)
		}
		// No appliance lock is taken: an apply may run at the same time.
	}
	h.sys.override = nil
	h.sys.reset()
	if err := RunJob(context.Background(), h.env, "plugin_restart-qdrant"); err != nil {
		t.Fatal(err)
	}
	if index(h.sys.lines(), DockerPath+" compose -p hm-qdrant restart") < 0 {
		t.Fatalf("%q", h.sys.lines())
	}
	// A plugin that is not in the document or not started: skipped, nothing run.
	h.sys.reset()
	if err := RunJob(context.Background(), h.env, "plugin_restart-hermes"); err != nil {
		t.Fatal(err)
	}
	if count(h.sys.lines(), DockerPath+" compose -p hm-hermes") != 0 {
		t.Fatalf("%q", h.sys.lines())
	}
	for _, bad := range []string{"plugin_restart-../../x", "shell", ""} {
		if err := RunJob(context.Background(), h.env, bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	h.env.Switches.AllowPlugins = false
	h.sys.reset()
	_ = RunJob(context.Background(), h.env, "plugin_restart-qdrant")
	_ = RunJob(context.Background(), h.env, "vectorize_sync")
	if len(h.sys.lines()) != 0 {
		t.Fatalf("switch off: %q", h.sys.lines())
	}
}

// backupHarness has a mounted NAS destination, two plugins with volumes and
// a backup key.
func backupHarness(t *testing.T, include bool) (*harness, backup.Key) {
	h := newHarness(t)
	h.env.Switches.AllowForeignContainers = true
	for _, v := range []string{"hm-qdrant_storage", "hm-assistant_data", "hm-ollama_models"} {
		h.sys.volumes[v] = true
	}
	doc := pluginsDoc(1, plug("ollama", true, nil), plug("qdrant", true, nil), plug("assistant", true, nil))
	doc["nas"] = []map[string]any{nfsEntry("bk", "nas", "/volume1/backup", "", "write")}
	doc["backup"] = map[string]any{"enabled": true, "destination": map[string]any{"kind": "nas", "nas_id": "bk", "subpath": "hm/backups"},
		"include_models": include, "keep": 2}
	h.mustApply(doc)
	for _, v := range []string{"hm-qdrant_storage", "hm-assistant_data", "hm-ollama_models"} {
		dir := filepath.Join(h.env.Paths.DockerVolumes, v, "_data")
		h.writeFile(filepath.Join(dir, "data.bin"), "content of "+v, 0o600)
	}
	key, err := backup.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.SaveKey(h.env.Paths.backupKeyPath(), key); err != nil {
		t.Fatal(err)
	}
	h.setAgentState("3f1c2b9e-0000-4000-8000-000000000001", "2026-10-02T11:59:00Z", "0.2.0")
	h.sys.reset()
	return h, key
}

func TestBackupRunStopsArchivesAndStarts(t *testing.T) {
	h, key := backupHarness(t, false)
	if err := RunJob(context.Background(), h.env, "backup_run"); err != nil {
		t.Fatal(err)
	}
	lines := h.sys.lines()
	stopA := index(lines, DockerPath+" compose -p hm-assistant stop")
	stopQ := index(lines, DockerPath+" compose -p hm-qdrant stop")
	startQ := index(lines, DockerPath+" compose -p hm-qdrant start")
	startA := index(lines, DockerPath+" compose -p hm-assistant start")
	if stopA < 0 || stopQ < stopA || startQ < stopQ || startA < startQ {
		t.Fatalf("order: %q", lines)
	}
	if index(lines, DockerPath+" compose -p hm-ollama stop") >= 0 {
		t.Fatal("ollama's only volume holds models, which are not saved: it is not stopped")
	}
	st := h.state()
	if st.Backup.State != appliance.BackupOK || st.Backup.LastSizeBytes <= 0 || st.Backup.LastOKAt == "" {
		t.Fatalf("%+v", st.Backup)
	}
	dir := filepath.Join(h.env.Paths.mountPoint("bk"), "hm", "backups")
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "hm-backup-3f1c2b9e-0000-4000-8000-000000000001-20261002T120000Z") {
		t.Fatalf("%v", entries)
	}
	// Restore it with the recovery key into a new directory.
	var out, prompt bytes.Buffer
	archive := filepath.Join(dir, entries[0].Name())
	if err := BackupRestore(context.Background(), h.env, archive, "", strings.NewReader(backup.FormatRecoveryKey(key)+"\n"), &prompt, &out); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(h.env.Paths.state("restore"), "20261002T120000Z")
	for rel, want := range map[string]string{
		"volumes/qdrant/storage/data.bin": "content of hm-qdrant_storage",
		"volumes/assistant/data/data.bin": "content of hm-assistant_data",
	} {
		got, err := os.ReadFile(filepath.Join(restored, rel))
		if err != nil || string(got) != want {
			t.Fatalf("%s: %q %v", rel, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(restored, "volumes/ollama")); err == nil {
		t.Fatal("models are saved only with include_models")
	}
	if _, err := os.Stat(filepath.Join(restored, "document", "applied.json")); err != nil {
		t.Fatal("the applied document is saved")
	}
	// The wrong key is refused before anything is written.
	other, _ := backup.NewKey()
	err := BackupRestore(context.Background(), h.env, archive, filepath.Join(h.root, "r2"), strings.NewReader(backup.FormatRecoveryKey(other)+"\n"), &prompt, &out)
	if err == nil || !strings.Contains(err.Error(), "not the key") {
		t.Fatal(err)
	}
	// Two more runs: keep = 2 removes the oldest.
	for i := 1; i <= 2; i++ {
		h.now = h.now.Add(time.Duration(i) * time.Hour)
		if err := RunJob(context.Background(), h.env, "backup_run"); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ = os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("%v", entries)
	}
}

func TestBackupIncludeModels(t *testing.T) {
	h, _ := backupHarness(t, true)
	if err := RunJob(context.Background(), h.env, "backup_run"); err != nil {
		t.Fatal(err)
	}
	if index(h.sys.lines(), DockerPath+" compose -p hm-ollama stop") < 0 || index(h.sys.lines(), DockerPath+" compose -p hm-ollama start") < 0 {
		t.Fatalf("%q", h.sys.lines())
	}
}

func TestBackupRestartsPluginsOnFailure(t *testing.T) {
	h, _ := backupHarness(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.sys.override = func(argv []string) (fakeResp, bool) {
		if strings.Join(argv, " ") == DockerPath+" compose -p hm-qdrant stop" {
			cancel() // the run fails after the plugins were stopped
		}
		return fakeResp{}, false
	}
	if err := RunJob(ctx, h.env, "backup_run"); err == nil {
		t.Fatal("the backup must fail")
	}
	lines := h.sys.lines()
	if index(lines, DockerPath+" compose -p hm-qdrant start") < 0 || index(lines, DockerPath+" compose -p hm-assistant start") < 0 {
		t.Fatalf("plugins must be started again after a failure: %q", lines)
	}
	if st := h.state(); st.Backup.State != appliance.BackupError {
		t.Fatalf("%+v", st.Backup)
	}
	entries, _ := os.ReadDir(filepath.Join(h.env.Paths.mountPoint("bk"), "hm", "backups"))
	for _, e := range entries {
		if _, _, err := backup.ParseArchiveName(e.Name()); err == nil {
			t.Fatalf("a failed run left an archive: %s", e.Name())
		}
	}
	// A plugin that cannot be stopped fails the run and is started again.
	h.sys.override = func(argv []string) (fakeResp, bool) {
		if strings.Join(argv, " ") == DockerPath+" compose -p hm-assistant stop" {
			return fakeResp{code: 1, stderr: "timeout"}, true
		}
		return fakeResp{}, false
	}
	h.sys.reset()
	if err := RunJob(context.Background(), h.env, "backup_run"); err == nil {
		t.Fatal("must fail")
	}
	if index(h.sys.lines(), DockerPath+" compose -p hm-assistant start") < 0 || index(h.sys.lines(), DockerPath+" compose -p hm-qdrant stop") >= 0 {
		t.Fatalf("%q", h.sys.lines())
	}
}

func TestBackupDestinationAndPreconditions(t *testing.T) {
	cases := map[string]struct {
		prepare func(h *harness)
		state   string
		detail  string
	}{
		"not mounted": {func(h *harness) {
			h.writeFile(h.env.Paths.MountInfo, "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n", 0o644)
		}, appliance.BackupError, "not mounted"},
		"mounted read-only": {func(h *harness) {
			h.writeFile(h.env.Paths.MountInfo, "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n90 22 0:9 / "+h.env.Paths.mountPoint("bk")+" ro - nfs nas:/volume1/backup ro\n", 0o644)
		}, appliance.BackupError, "read-write"},
		"not mounted by HappyMining": {func(h *harness) {
			_, _ = h.env.updateState(func(st *State) { st.nas("bk").Mounted = false })
		}, appliance.BackupError, "not mounted by HappyMining"},
		"no key": {func(h *harness) { _ = os.Remove(h.env.Paths.backupKeyPath()) }, appliance.BackupNoKey, "backup init"},
		"no machine id": {func(h *harness) {
			h.setAgentState("", "", "0.2.0")
		}, appliance.BackupError, "machine id"},
		"volume outside Docker's directory": {func(h *harness) {
			h.sys.override = func(argv []string) (fakeResp, bool) {
				if strings.Join(argv, " ") == DockerPath+" volume inspect --format {{.Mountpoint}} hm-qdrant_storage" {
					return fakeResp{stdout: "/etc\n"}, true
				}
				return fakeResp{}, false
			}
		}, appliance.BackupError, "is not under"},
		"volume is a link": {func(h *harness) {
			link := filepath.Join(h.env.Paths.DockerVolumes, "evil")
			_ = os.Symlink(h.root, link)
			h.sys.override = func(argv []string) (fakeResp, bool) {
				if strings.Join(argv, " ") == DockerPath+" volume inspect --format {{.Mountpoint}} hm-qdrant_storage" {
					return fakeResp{stdout: link + "\n"}, true
				}
				return fakeResp{}, false
			}
		}, appliance.BackupError, "symbolic link"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h, _ := backupHarness(t, false)
			c.prepare(h)
			h.sys.reset()
			_ = RunJob(context.Background(), h.env, "backup_run")
			st := h.state()
			if st.Backup.State != c.state || !strings.Contains(st.Backup.Detail, c.detail) {
				t.Fatalf("%+v", st.Backup)
			}
			if count(h.sys.lines(), DockerPath+" compose -p hm-qdrant stop") != 0 {
				t.Fatalf("nothing is stopped when the run cannot happen: %q", h.sys.lines())
			}
		})
	}
	t.Run("not configured", func(t *testing.T) {
		h := newHarness(t)
		h.mustApply(pluginsDoc(1))
		if err := RunJob(context.Background(), h.env, "backup_run"); err != nil {
			t.Fatal(err)
		}
		if st := h.state(); st.Backup.State != appliance.BackupDisabled || st.job("backup_run").LastStatus != appliance.RunSkipped {
			t.Fatalf("%+v", st.Backup)
		}
	})
	t.Run("switch off", func(t *testing.T) {
		h, _ := backupHarness(t, false)
		h.env.Switches.AllowBackup = false
		_ = RunJob(context.Background(), h.env, "backup_run")
		if len(h.sys.lines()) != 0 {
			t.Fatalf("%q", h.sys.lines())
		}
	})
	t.Run("s3 secret unreadable", func(t *testing.T) {
		h := newHarness(t)
		doc := pluginsDoc(1)
		doc["backup"] = map[string]any{"enabled": true, "destination": map[string]any{"kind": "s3", "endpoint": "https://s3.example.com",
			"region": "eu-west-3", "bucket": "bucket-1", "prefix": "hm", "access_key_id": "AKIAEXAMPLE", "secret": "backup.s3.secret_key"},
			"include_models": false, "keep": 3}
		doc["secrets"] = map[string]any{"backup.s3.secret_key": newHarness(t).sealFor("backup.s3.secret_key", "x")}
		h.mustApply(doc)
		key, _ := backup.NewKey()
		_ = backup.SaveKey(h.env.Paths.backupKeyPath(), key)
		h.setAgentState("m-1", "", "0.2.0")
		_ = RunJob(context.Background(), h.env, "backup_run")
		if st := h.state(); st.Backup.State != appliance.BackupError || !strings.Contains(st.Backup.Detail, "unreadable") {
			t.Fatalf("%+v", st.Backup)
		}
	})
}

func TestBackupInitAndRestoreArguments(t *testing.T) {
	h := newHarness(t)
	var out bytes.Buffer
	if err := BackupInit(h.env, &out); err != nil {
		t.Fatal(err)
	}
	key, err := backup.LoadKey(h.env.Paths.backupKeyPath(), h.env.OwnerUID)
	if err != nil || !strings.Contains(out.String(), backup.FormatRecoveryKey(key)) || mode(t, h.env.Paths.backupKeyPath()) != 0o600 {
		t.Fatalf("%v %s", err, out.String())
	}
	if err := BackupInit(h.env, &out); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatal("an existing key must never be replaced")
	}
	if strings.Contains(h.auditText(), backup.FormatRecoveryKey(key)) {
		t.Fatal("the recovery key reached the audit")
	}
	for _, args := range [][2]string{{"relative.hmbk", ""}, {"/abs.hmbk", "relative"}, {filepath.Join(h.root, "missing"), ""}} {
		if err := BackupRestore(context.Background(), h.env, args[0], args[1], strings.NewReader("x\n"), &out, &out); err == nil {
			t.Fatalf("%v accepted", args)
		}
	}
	link := filepath.Join(h.root, "link.hmbk")
	_ = os.Symlink(h.env.Paths.backupKeyPath(), link)
	if err := BackupRestore(context.Background(), h.env, link, "", strings.NewReader("x\n"), &out, &out); err == nil {
		t.Fatal("a symbolic link must be refused")
	}
}
