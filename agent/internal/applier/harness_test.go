package applier

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/config"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/execx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/seal"
)

// Every test works in its own temporary directory: every root of Paths is
// inside it, and the command runner is a fake that never runs a program. A
// regression can therefore never mount, unmount, run Docker or dpkg, or write
// a real system path.

const repoRoot = "../../.."

func fixtureCatalog() string { return filepath.Join(repoRoot, "appliance", "testdata", "catalog") }
func shippedCatalog() string { return filepath.Join(repoRoot, "appliance", "catalog") }
func fixtureDocs(kind string) string {
	return filepath.Join(repoRoot, "appliance", "testdata", "documents", kind)
}

func allOn() config.Helper {
	return config.Helper{AllowPlugins: true, AllowNAS: true, AllowBackup: true, AllowUpdate: true}
}

type harness struct {
	t     *testing.T
	root  string
	env   *Env
	sys   *fakeSys
	mu    sync.Mutex
	audit []string
	now   time.Time
	slept []time.Duration
}

// copyTree copies a directory of regular files (a catalog fixture) so that
// the copy belongs to the test's user with safe modes.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func newHarness(t *testing.T) *harness { return newHarnessWith(t, fixtureCatalog()) }

func newHarnessWith(t *testing.T, catalog string) *harness {
	t.Helper()
	root := t.TempDir()
	h := &harness{t: t, root: root, now: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	p := Paths{
		StateDir:       filepath.Join(root, "var/lib/happymining-helper"),
		PluginDataRoot: filepath.Join(root, "var/lib/happymining-plugins"),
		NASRoot:        filepath.Join(root, "srv/happymining/nas"),
		CatalogDir:     filepath.Join(root, "usr/share/happymining/catalog"),
		BuildRoot:      filepath.Join(root, "usr/share/happymining"),
		ReleaseKeysDir: filepath.Join(root, "usr/share/happymining/release-keys"),
		ProfilePath:    filepath.Join(root, "etc/happymining/appliance.json"),
		AgentStateDir:  filepath.Join(root, "var/lib/happymining"),
		MountInfo:      filepath.Join(root, "proc/self/mountinfo"),
		BootID:         filepath.Join(root, "proc/sys/kernel/random/boot_id"),
		DockerVolumes:  filepath.Join(root, "var/lib/docker/volumes"),
		InstallerCache: filepath.Join(root, "var/cache/happymining"),
	}
	for _, d := range []string{filepath.Dir(p.StateDir), filepath.Dir(p.NASRoot), p.BuildRoot, filepath.Dir(p.ProfilePath),
		p.AgentStateDir, filepath.Dir(p.MountInfo), filepath.Dir(p.BootID), p.DockerVolumes} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	copyTree(t, catalog, p.CatalogDir)
	if err := os.MkdirAll(filepath.Join(p.BuildRoot, "vectorizer"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.writeFile(p.MountInfo, "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n", 0o644)
	h.writeFile(p.BootID, "boot-1\n", 0o644)
	h.sys = newFakeSys(t, p)
	h.env = &Env{
		Paths: p, Runner: h.sys, Switches: allOn(), OwnerUID: uint32(os.Getuid()), AgentUID: uint32(os.Getuid()),
		Version: "0.2.0", Now: func() time.Time { return h.now },
		Sleep:     func(d time.Duration) { h.mu.Lock(); h.slept = append(h.slept, d); h.mu.Unlock() },
		Audit:     func(line string) { h.mu.Lock(); h.audit = append(h.audit, line); h.mu.Unlock() },
		HasDocker: func() bool { return true },
		// The test's own group: a test that does not run as root cannot give
		// files to the vectorizer's real group.
		VectorizerGID: &testGID,
	}
	return h
}

var testGID = os.Getgid()

func (h *harness) writeFile(path, content string, mode os.FileMode) {
	h.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) auditText() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.audit, "\n")
}

func (h *harness) state() *State {
	h.t.Helper()
	st, err := h.env.loadState()
	if err != nil {
		h.t.Fatal(err)
	}
	return st
}

func (h *harness) machineKey() *seal.PrivateKey {
	h.t.Helper()
	k, err := h.env.sealKey()
	if err != nil {
		h.t.Fatal(err)
	}
	return k
}

// sealFor seals a secret for the harness machine.
func (h *harness) sealFor(name, plain string) string {
	h.t.Helper()
	v, err := seal.Seal(h.machineKey().Public(), name, []byte(plain))
	if err != nil {
		h.t.Fatal(err)
	}
	return v
}

// fixture returns the "document" of a fixture file as a generic map.
func fixture(t *testing.T, kind, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureDocs(kind), name))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Document map[string]any `json:"document"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Document
}

// withSecrets replaces every sealed value with one sealed for the harness
// machine (plaintext "plain:<name>" unless given).
func (h *harness) withSecrets(doc map[string]any, plain map[string]string) map[string]any {
	secrets, _ := doc["secrets"].(map[string]any)
	for name := range secrets {
		p, ok := plain[name]
		if !ok {
			p = "plain:" + name
		}
		secrets[name] = h.sealFor(name, p)
	}
	return doc
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// quickApply runs QuickApply and, when it asked for the apply unit,
// ApplyStored (what systemd would do).
func (h *harness) apply(doc map[string]any) Outcome {
	h.t.Helper()
	out := QuickApply(context.Background(), h.env, mustJSON(h.t, doc))
	if out.OK && h.sys.started(UnitApply) {
		if err := ApplyStored(context.Background(), h.env); err != nil {
			h.t.Fatalf("apply-stored: %v", err)
		}
	}
	return out
}

// mustApply is apply for a document that must be accepted.
func (h *harness) mustApply(doc map[string]any) {
	h.t.Helper()
	if out := h.apply(doc); !out.OK {
		h.t.Fatalf("apply refused: %+v", out)
	}
}

func (h *harness) setProfile(v any) {
	h.t.Helper()
	h.writeFile(h.env.Paths.ProfilePath, string(mustJSON(h.t, v)), 0o644)
}

func (h *harness) setAgentState(machineID, heartbeat, version string) {
	h.t.Helper()
	h.writeFile(h.env.Paths.agentStatePath(), string(mustJSON(h.t, map[string]any{
		"state": "online", "machine_id": machineID, "last_heartbeat_ok": heartbeat, "agent_version": version,
	})), 0o600)
}

// ---------------------------------------------------------------- fake system

type fakeResp struct {
	code   int
	stdout string
	stderr string
	err    error
}

// fakeSys stands for the kernel's mount table, Docker and systemd. It never
// runs a program.
type fakeSys struct {
	mu       sync.Mutex
	t        *testing.T
	p        Paths
	calls    [][]string
	network  bool
	images   map[string]bool
	projects map[string]string // id -> running | exited
	foreign  int
	volumes  map[string]bool
	nextID   int
	// override answers a command before the simulation; ok=false passes.
	override func(argv []string) (fakeResp, bool)
	// psError makes `docker ps` fail.
	psError bool
}

func newFakeSys(t *testing.T, p Paths) *fakeSys {
	return &fakeSys{t: t, p: p, images: map[string]bool{}, projects: map[string]string{}, volumes: map[string]bool{}, nextID: 100}
}

func (f *fakeSys) Run(_ context.Context, _ time.Duration, path string, args ...string) (execx.Result, error) {
	argv := append([]string{path}, args...)
	f.mu.Lock()
	f.calls = append(f.calls, argv)
	override := f.override
	f.mu.Unlock()
	if override != nil {
		if r, ok := override(argv); ok {
			return execx.Result{Stdout: []byte(r.stdout), Stderr: []byte(r.stderr), ExitCode: r.code}, r.err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.simulate(argv)
	return execx.Result{Stdout: []byte(r.stdout), Stderr: []byte(r.stderr), ExitCode: r.code}, r.err
}

func escapeMount(s string) string {
	r := strings.NewReplacer(" ", `\040`, "\t", `\011`, "\n", `\012`, `\`, `\134`)
	return r.Replace(s)
}

func (f *fakeSys) simulate(argv []string) fakeResp {
	switch argv[0] {
	case SystemctlPath, DpkgPath:
		return fakeResp{}
	case MountPath:
		// mount -t <type> <source> <target> -o <opts>
		if len(argv) != 7 || argv[1] != "-t" || argv[5] != "-o" {
			return fakeResp{code: 1, stderr: "bad mount argv"}
		}
		opts := strings.Split(argv[6], ",")
		f.nextID++
		line := fmt.Sprintf("%d 22 0:%d / %s %s,relatime shared:9 - %s %s %s,vers=3\n", f.nextID, f.nextID,
			escapeMount(argv[4]), opts[0], argv[2], escapeMount(argv[3]), opts[0])
		mi, _ := os.ReadFile(f.p.MountInfo)
		_ = os.WriteFile(f.p.MountInfo, append(mi, line...), 0o644)
		return fakeResp{}
	case UmountPath:
		mi, _ := os.ReadFile(f.p.MountInfo)
		var keep []string
		removed := false
		for _, l := range strings.Split(strings.TrimRight(string(mi), "\n"), "\n") {
			fields := strings.Split(l, " ")
			if len(fields) > 4 && fields[4] == escapeMount(argv[1]) && !removed {
				removed = true
				continue
			}
			keep = append(keep, l)
		}
		if !removed {
			return fakeResp{code: 32, stderr: "umount: not mounted"}
		}
		_ = os.WriteFile(f.p.MountInfo, []byte(strings.Join(keep, "\n")+"\n"), 0o644)
		return fakeResp{}
	case DockerPath:
		return f.docker(argv[1:])
	}
	return fakeResp{code: 127, stderr: "fake: unknown program " + argv[0]}
}

func (f *fakeSys) docker(a []string) fakeResp {
	switch {
	case len(a) >= 4 && a[0] == "compose" && a[1] == "-p":
		id := strings.TrimPrefix(a[2], ProjectPrefix)
		rest := a[3:]
		switch {
		case len(rest) >= 6 && rest[0] == "--env-file" && rest[2] == "-f" && rest[4] == "up" && rest[5] == "-d":
			f.projects[id] = "running"
		case rest[0] == "down":
			delete(f.projects, id)
		case rest[0] == "stop":
			if _, ok := f.projects[id]; ok {
				f.projects[id] = "exited"
			}
		case rest[0] == "start", rest[0] == "restart":
			if _, ok := f.projects[id]; ok {
				f.projects[id] = "running"
			}
		case rest[0] == "ps":
			st, ok := f.projects[id]
			if !ok {
				return fakeResp{}
			}
			return fakeResp{stdout: fmt.Sprintf(`{"Name":"%s-%s-1","Service":"%s","State":"%s","Health":"","ExitCode":0,"Publishers":null}`+"\n",
				a[2], id, id, st)}
		case rest[0] == "exec":
			if f.projects[id] != "running" {
				return fakeResp{code: 1, stderr: "service is not running"}
			}
		}
		return fakeResp{}
	case len(a) == 3 && a[0] == "network" && a[1] == "inspect":
		if !f.network {
			return fakeResp{code: 1, stderr: "Error response from daemon: network hm-appliance not found"}
		}
		return fakeResp{stdout: "[]"}
	case len(a) == 3 && a[0] == "network" && a[1] == "create":
		f.network = true
		return fakeResp{stdout: "abc\n"}
	case len(a) == 5 && a[0] == "image" && a[1] == "inspect":
		if !f.images[a[4]] {
			return fakeResp{code: 1, stderr: "Error: No such image"}
		}
		return fakeResp{stdout: "sha256:1\n"}
	case len(a) == 4 && a[0] == "build":
		f.images[a[2]] = true
		return fakeResp{}
	case len(a) >= 1 && a[0] == "ps":
		if f.psError {
			return fakeResp{code: 1, stderr: "Cannot connect to the Docker daemon"}
		}
		var b strings.Builder
		for i := 0; i < f.foreign; i++ {
			fmt.Fprintf(&b, "foreign%d\t\n", i)
		}
		ids := make([]string, 0, len(f.projects))
		for id := range f.projects {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if f.projects[id] == "running" {
				fmt.Fprintf(&b, "c-%s\t%s\n", id, id)
			}
		}
		return fakeResp{stdout: b.String()}
	case len(a) == 5 && a[0] == "volume" && a[1] == "inspect":
		name := a[4]
		if !f.volumes[name] {
			return fakeResp{code: 1, stderr: "Error: No such volume: " + name}
		}
		dir := filepath.Join(f.p.DockerVolumes, name, "_data")
		_ = os.MkdirAll(dir, 0o755)
		return fakeResp{stdout: dir + "\n"}
	case len(a) >= 1 && a[0] == "volume" && a[1] == "ls":
		var names []string
		for n := range f.volumes {
			names = append(names, n)
		}
		sort.Strings(names)
		return fakeResp{stdout: strings.Join(names, "\n") + "\n"}
	case len(a) == 3 && a[0] == "volume" && a[1] == "rm":
		delete(f.volumes, a[2])
		return fakeResp{}
	}
	return fakeResp{code: 125, stderr: "fake docker: unknown command"}
}

// lines returns the recorded command lines.
func (f *fakeSys) lines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	for i, c := range f.calls {
		out[i] = strings.Join(c, " ")
	}
	return out
}

func (f *fakeSys) argvs() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.calls...)
}

func (f *fakeSys) reset() {
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
}

func (f *fakeSys) started(unit string) bool {
	for _, l := range f.lines() {
		if l == SystemctlPath+" start --no-block "+unit {
			return true
		}
	}
	return false
}

// index returns the position of the first line with the prefix, or -1.
func index(lines []string, prefix string) int {
	for i, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return i
		}
	}
	return -1
}

func count(lines []string, prefix string) int {
	n := 0
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

// mode returns the permission bits of a file.
func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// assertNoCommandEscapes checks that every program run is one of the five
// fixed ones and that no argument is a shell.
func assertFixedPrograms(t *testing.T, sys *fakeSys) {
	t.Helper()
	for _, argv := range sys.argvs() {
		switch argv[0] {
		case DockerPath, MountPath, UmountPath, DpkgPath, SystemctlPath:
		default:
			t.Errorf("unexpected program %q", argv[0])
		}
		for _, a := range argv[1:] {
			if a == "sh" || a == "-c" || a == "/bin/sh" || a == "bash" {
				t.Errorf("shell in argv: %q", argv)
			}
		}
	}
}
