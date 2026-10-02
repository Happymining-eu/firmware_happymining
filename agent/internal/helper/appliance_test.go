package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/applier"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/execx"
)

// applianceFixture is a helper whose every appliance path is inside a
// temporary directory and whose runner is a fake.
func applianceFixture(t *testing.T, conf string) *fixture {
	t.Helper()
	f := newFixture(t, conf)
	root := t.TempDir()
	p := applier.Paths{
		StateDir:       filepath.Join(root, "state"),
		PluginDataRoot: filepath.Join(root, "plugins"),
		NASRoot:        filepath.Join(root, "srv", "nas"),
		CatalogDir:     filepath.Join(root, "catalog"),
		BuildRoot:      filepath.Join(root, "share"),
		ReleaseKeysDir: filepath.Join(root, "keys"),
		ProfilePath:    filepath.Join(root, "etc", "appliance.json"),
		AgentStateDir:  filepath.Join(root, "agent"),
		MountInfo:      filepath.Join(root, "mountinfo"),
		BootID:         filepath.Join(root, "boot_id"),
		DockerVolumes:  filepath.Join(root, "volumes"),
	}
	src := filepath.Join("..", "..", "..", "appliance", "testdata", "catalog")
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(p.CatalogDir, rel), 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(p.CatalogDir, rel), data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(p.MountInfo, []byte("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"), 0o644)
	_ = os.WriteFile(p.BootID, []byte("b1\n"), 0o644)
	f.deps.Paths = p
	f.deps.AgentUID = uint32(os.Getuid())
	f.deps.Version = "0.2.0"
	f.deps.HasDocker = func() bool { return true }
	f.runner.On("/usr/bin/systemctl start --no-block happymining-appliance-apply.service", execx.FakeResponse{})
	f.runner.On("/usr/bin/systemctl start --no-block happymining-appliance-job@backup_run.service", execx.FakeResponse{})
	f.runner.On("/usr/bin/systemctl start --no-block happymining-appliance-job@status_refresh.service", execx.FakeResponse{})
	return f
}

const validDoc = `{"schema":1,"revision":4,"mode":"private_ai","plugins":[{"id":"qdrant","enabled":true,"settings":{}}]}`

func TestValidateFieldsBelongToTheirAction(t *testing.T) {
	doc := json.RawMessage(validDoc)
	good := []Request{
		{Action: ActionApplianceStatus},
		{Action: ActionApplianceApply, Document: doc},
		{Action: ActionApplianceRunJob, Job: JobVectorizeSync},
		{Action: ActionApplianceRunJob, Job: JobBackupRun},
		{Action: ActionApplianceRunJob, Job: JobPluginRestart, Plugin: "open-webui"},
		{Action: ActionUpdateInstall, Version: "0.3.0", ManifestB64: "e30=", SignatureB64: "c2ln", ArtifactPath: "/var/lib/happymining/updates/x.deb"},
	}
	for _, r := range good {
		if err := r.Validate(); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	bad := []Request{
		{Action: ActionApplianceStatus, Job: JobBackupRun},
		{Action: ActionApplianceStatus, Document: doc},
		{Action: ActionApplianceApply},
		{Action: ActionApplianceApply, Document: doc, Plugin: "x"},
		{Action: ActionApplianceApply, Document: json.RawMessage(`"` + strings.Repeat("x", 70*1024) + `"`)},
		{Action: ActionApplianceRunJob},
		{Action: ActionApplianceRunJob, Job: "update_check"},
		{Action: ActionApplianceRunJob, Job: "status_refresh"},
		{Action: ActionApplianceRunJob, Job: "shell"},
		{Action: ActionApplianceRunJob, Job: JobPluginRestart},
		{Action: ActionApplianceRunJob, Job: JobPluginRestart, Plugin: "../x"},
		{Action: ActionApplianceRunJob, Job: JobPluginRestart, Plugin: "x y"},
		{Action: ActionApplianceRunJob, Job: JobBackupRun, Plugin: "x"},
		{Action: ActionApplianceRunJob, Job: JobBackupRun, Document: doc},
		{Action: ActionUpdateInstall, Version: "0.3", ManifestB64: "e30=", SignatureB64: "c2ln", ArtifactPath: "/a/x.deb"},
		{Action: ActionUpdateInstall, Version: "0.3.0", ManifestB64: "not base64!", SignatureB64: "c2ln", ArtifactPath: "/a/x.deb"},
		{Action: ActionUpdateInstall, Version: "0.3.0", ManifestB64: "e30=", SignatureB64: "", ArtifactPath: "/a/x.deb"},
		{Action: ActionUpdateInstall, Version: "0.3.0", ManifestB64: "e30=", SignatureB64: "c2ln", ArtifactPath: "relative.deb"},
		{Action: ActionUpdateInstall, Version: "0.3.0", ManifestB64: "e30=", SignatureB64: "c2ln", ArtifactPath: "/a/../b.deb"},
		{Action: ActionUpdateInstall, Version: "0.3.0", ManifestB64: "e30=", SignatureB64: "c2ln", ArtifactPath: "/a/x.deb", Job: "x"},
		{Action: ActionUpdateInstall, Version: "0.3.0", ManifestB64: strings.Repeat("A", 22000), SignatureB64: "c2ln", ArtifactPath: "/a/x.deb"},
		{Action: ActionRestartVastDaemon, Job: JobBackupRun},
		{Action: ActionReboot, DelayS: ptr(120), Document: doc},
		{Action: ActionReboot, DelayS: ptr(120), Plugin: "x"},
	}
	for _, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("%+v must be refused", r)
		}
	}
}

func TestDecodeRequestSizeLimitsPerAction(t *testing.T) {
	pad := func(n int) string { return strings.Repeat(" ", n) }
	// 256 bytes for every action but the two big ones.
	if _, err := DecodeRequest(strings.NewReader(`{"action":"appliance-status"` + pad(240) + "}\n")); err == nil {
		t.Fatal("a status request over 256 bytes must be refused")
	}
	if _, err := DecodeRequest(strings.NewReader(`{"action":"appliance-status"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	// An apply request of about 90 KiB (64 KiB document plus white space).
	big := `{"action":"appliance-apply","document":` + validDoc[:len(validDoc)-1] + pad(60*1024) + `}` + pad(25*1024) + "}\n"
	if _, err := DecodeRequest(strings.NewReader(big)); err != nil {
		t.Fatalf("a 90 KiB apply request: %v", err)
	}
	huge := `{"action":"appliance-apply","document":` + validDoc + pad(97*1024) + "}\n"
	if _, err := DecodeRequest(strings.NewReader(huge)); err == nil {
		t.Fatal("over 96 KiB must be refused")
	}
	upd := `{"action":"update-install","version":"0.3.0","manifest_b64":"` + strings.Repeat("A", 21848) +
		`","signature_b64":"c2ln","artifact_path":"/var/lib/happymining/updates/x.deb"}` + "\n"
	if _, err := DecodeRequest(strings.NewReader(upd)); err != nil {
		t.Fatalf("an update request with a 16 KiB manifest: %v", err)
	}
	if _, err := DecodeRequest(strings.NewReader(`{"action":"update-install"` + pad(33*1024) + "}\n")); err == nil {
		t.Fatal("an update request over 32 KiB must be refused")
	}
	if _, err := DecodeRequest(strings.NewReader(`{"action":"reboot","delay_s":120,"document":{}}` + "\n")); err == nil {
		t.Fatal("a field of another action must be refused")
	}
}

func TestApplianceActionsThroughExecute(t *testing.T) {
	f := applianceFixture(t, "ALLOW_PLUGINS=1\n")
	ctx := context.Background()

	resp := Execute(ctx, Request{Action: ActionApplianceApply, Document: json.RawMessage(validDoc)}, f.deps)
	if !resp.OK {
		t.Fatalf("%+v", resp)
	}
	var ar ApplyResult
	if err := json.Unmarshal(resp.Result, &ar); err != nil || ar.ApplyStatus != "pending" {
		t.Fatalf("%s %v", resp.Result, err)
	}
	if calls := f.runner.CallLog(); len(calls) != 1 || calls[0] != "/usr/bin/systemctl start --no-block happymining-appliance-apply.service" {
		t.Fatalf("%q", calls)
	}

	resp = Execute(ctx, Request{Action: ActionApplianceStatus}, f.deps)
	if !resp.OK {
		t.Fatalf("%+v", resp)
	}
	var sr StatusResult
	if err := json.Unmarshal(resp.Result, &sr); err != nil {
		t.Fatal(err)
	}
	if sr.Reported.Control != "cloud" || !strings.HasPrefix(sr.Reported.SealPublicKey, "hmk1.") || len(sr.Reported.Catalog) != 4 ||
		sr.Reported.ApplyStatus != "pending" || !sr.Reported.Capabilities.Plugins || sr.Reported.Capabilities.NAS {
		t.Fatalf("%+v", sr.Reported)
	}

	resp = Execute(ctx, Request{Action: ActionApplianceRunJob, Job: JobBackupRun}, f.deps)
	if resp.OK || resp.Code != CodeDisabled {
		t.Fatalf("backup is off: %+v", resp)
	}
	resp = Execute(ctx, Request{Action: ActionApplianceRunJob, Job: JobPluginRestart, Plugin: "ollama"}, f.deps)
	if resp.OK || resp.Code != CodeInvalid {
		t.Fatalf("not in the document: %+v", resp)
	}
	resp = Execute(ctx, Request{Action: ActionUpdateInstall, Version: "0.3.0", ManifestB64: "e30=", SignatureB64: "c2ln",
		ArtifactPath: "/var/lib/happymining/updates/x.deb"}, f.deps)
	if resp.OK || resp.Code != CodeDisabled {
		t.Fatalf("update is off: %+v", resp)
	}
	// Local control.
	_ = os.MkdirAll(filepath.Dir(f.deps.Paths.ProfilePath), 0o755)
	_ = os.WriteFile(f.deps.Paths.ProfilePath, []byte(`{"schema":1,"control":"local"}`), 0o644)
	resp = Execute(ctx, Request{Action: ActionApplianceApply, Document: json.RawMessage(validDoc)}, f.deps)
	if resp.OK || resp.Code != CodeLocallyControlled {
		t.Fatalf("%+v", resp)
	}
}

func TestApplianceActionsNeedConfiguredPaths(t *testing.T) {
	f := newFixture(t, "ALLOW_PLUGINS=1\nALLOW_NAS=1\n")
	for _, req := range []Request{{Action: ActionApplianceStatus}, {Action: ActionApplianceApply, Document: json.RawMessage(validDoc)},
		{Action: ActionApplianceRunJob, Job: JobBackupRun}} {
		resp := Execute(context.Background(), req, f.deps)
		if resp.OK || resp.Code != CodeFailed || !strings.Contains(resp.Detail, "not configured") {
			t.Fatalf("%s: %+v", req.Action, resp)
		}
	}
	if calls := f.runner.CallLog(); len(calls) != 0 {
		t.Fatalf("%q", calls)
	}
}

func TestApplianceSwitchFileUnusable(t *testing.T) {
	f := applianceFixture(t, "ALLOW_PLUGINS=1\n")
	_ = os.Chmod(f.conf, 0o666)
	resp := Execute(context.Background(), Request{Action: ActionApplianceApply, Document: json.RawMessage(validDoc)}, f.deps)
	if resp.OK || resp.Code != CodeDisabled {
		t.Fatalf("%+v", resp)
	}
}

func TestSocketCarriesLargeRequestsAndResults(t *testing.T) {
	f := applianceFixture(t, "ALLOW_PLUGINS=1\n")
	client, stop := serveOnce(t, f, []uint32{uint32(os.Getuid())})
	defer stop()
	// A document of about 60 KiB (white space inside it is insignificant).
	doc := validDoc[:len(validDoc)-1] + strings.Repeat(" ", 60*1024) + "}"
	resp, err := client.Do(context.Background(), Request{Action: ActionApplianceApply, Document: json.RawMessage(doc)})
	if err != nil || !resp.OK {
		t.Fatalf("%+v %v", resp, err)
	}
	resp, err = client.Do(context.Background(), Request{Action: ActionApplianceStatus})
	if err != nil || !resp.OK || len(resp.Result) == 0 {
		t.Fatalf("%+v %v", resp, err)
	}
}

// fakeServer answers every connection with the given line.
func fakeServer(t *testing.T, line string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = bufio.NewReader(conn).ReadSlice('\n')
			_, _ = conn.Write([]byte(line))
			_ = conn.Close()
		}
	}()
	return sock
}

func TestClientReadsLongResponsesWithinTheBound(t *testing.T) {
	result := `{"x":"` + strings.Repeat("a", 200*1024) + `"}`
	sock := fakeServer(t, `{"ok":true,"detail":"","result":`+result+"}\n")
	c := &Client{SocketPath: sock, Timeout: 5 * time.Second}
	resp, err := c.Do(context.Background(), Request{Action: ActionApplianceStatus})
	if err != nil || !resp.OK || len(resp.Result) != len(result) {
		t.Fatalf("%v %d", err, len(resp.Result))
	}
	sock = fakeServer(t, `{"ok":true,"detail":"`+strings.Repeat("a", 300*1024)+`"}`+"\n")
	c = &Client{SocketPath: sock, Timeout: 5 * time.Second}
	if _, err := c.Do(context.Background(), Request{Action: ActionApplianceStatus}); err == nil {
		t.Fatal("a response over 256 KiB must be refused")
	}
}
