package collector

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/execx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
)

const smiLine = "/usr/bin/nvidia-smi --query-gpu=index,uuid,name,driver_version,memory.total,memory.used,utilization.gpu,power.draw,temperature.gpu,fan.speed --format=csv,noheader,nounits"

func TestParseNvidiaSMIMultiGPU(t *testing.T) {
	out := `0, GPU-6f0c1a2b-0000-1111-2222-333344445555, NVIDIA GeForce RTX 4090, 550.120, 24564, 12, 0, 34.80, 41, 30
1, GPU-7a1d2b3c-0000-1111-2222-333344445555, NVIDIA GeForce RTX 4090, 550.120, 24564, 20211, 98, 412.15, 77, 85
`
	gpus, skipped := ParseNvidiaSMI(out)
	if skipped != 0 || len(gpus) != 2 {
		t.Fatalf("gpus=%d skipped=%d", len(gpus), skipped)
	}
	g := gpus[1]
	if g.Index != 1 || g.UUID != "GPU-7a1d2b3c-0000-1111-2222-333344445555" || g.Name != "NVIDIA GeForce RTX 4090" || g.DriverVersion != "550.120" {
		t.Fatalf("identity: %+v", g)
	}
	if *g.VRAMTotalMiB != 24564 || *g.VRAMUsedMiB != 20211 || *g.UtilPct != 98 || *g.PowerW != 412.15 || *g.TempC != 77 || *g.FanPct != 85 {
		t.Fatalf("values: %+v", g)
	}
	if *gpus[0].UtilPct != 0 {
		t.Fatal("a real 0 must stay 0")
	}
}

func TestParseNvidiaSMIMissingValuesBecomeNull(t *testing.T) {
	out := strings.Join([]string{
		"0, GPU-aaaa, NVIDIA H100 80GB HBM3, 550.120, 81559, 3, 0, 71.02, 33, [N/A]",
		"1, GPU-bbbb, NVIDIA A100, 550.120, 81920, [Not Supported], [N/A], [Not Supported], N/A, ",
		"2, [N/A], [Unknown Error], [N/A], [N/A], [N/A], [N/A], [N/A], [N/A], [N/A]",
		"3, GPU-dddd, Tesla T4, 550.120, 15360 MiB, 100, ERR!, 999999, -400, 250",
	}, "\n")
	gpus, skipped := ParseNvidiaSMI(out)
	if skipped != 0 || len(gpus) != 4 {
		t.Fatalf("gpus=%d skipped=%d", len(gpus), skipped)
	}
	if gpus[0].FanPct != nil || *gpus[0].TempC != 33 {
		t.Fatalf("[N/A] fan must be null: %+v", gpus[0])
	}
	g := gpus[1]
	if g.VRAMUsedMiB != nil || g.UtilPct != nil || g.PowerW != nil || g.TempC != nil || g.FanPct != nil {
		t.Fatalf("all missing values must be null: %+v", g)
	}
	if *g.VRAMTotalMiB != 81920 {
		t.Fatalf("present value lost: %+v", g)
	}
	g = gpus[2]
	if g.UUID != "" || g.Name != "" || g.DriverVersion != "" || g.VRAMTotalMiB != nil {
		t.Fatalf("markers must not become strings or numbers: %+v", g)
	}
	g = gpus[3]
	if g.VRAMTotalMiB != nil || g.UtilPct != nil || g.PowerW != nil || g.TempC != nil || g.FanPct != nil {
		t.Fatalf("unparseable or absurd values must be null: %+v", g)
	}

	// The JSON must say null, never 0.
	raw, _ := json.Marshal(gpus[1])
	for _, key := range []string{"vram_used_mib", "util_pct", "power_w", "temp_c", "fan_pct"} {
		if !strings.Contains(string(raw), `"`+key+`":null`) {
			t.Errorf("%s must serialise as null: %s", key, raw)
		}
	}
}

func TestParseNvidiaSMIRobustness(t *testing.T) {
	out := strings.Join([]string{
		"",
		"garbage line",
		"x, GPU-a, Name, 1, 1, 1, 1, 1, 1, 1", // bad index
		"0, GPU-a, Name, with, comma, 550.1, 8192, 1, 2, 3, 4, 5", // commas in the name
		"0, GPU-dup, Dup, 550.1, 8192, 1, 2, 3, 4, 5",             // duplicate index
		"No devices were found",
	}, "\n")
	gpus, skipped := ParseNvidiaSMI(out)
	if len(gpus) != 1 || skipped != 4 {
		t.Fatalf("gpus=%d skipped=%d: %+v", len(gpus), skipped, gpus)
	}
	if !strings.Contains(gpus[0].Name, "with") || gpus[0].DriverVersion != "550.1" || *gpus[0].FanPct != 5 {
		t.Fatalf("name with commas mis-parsed: %+v", gpus[0])
	}
	var many []string
	for i := 0; i < 40; i++ {
		many = append(many, strings.Replace("N, GPU-x, Name, 1.0, 8192, 1, 2, 3, 4, 5", "N", string(rune('0'+i/10))+string(rune('0'+i%10)), 1))
	}
	gpus, skipped = ParseNvidiaSMI(strings.Join(many, "\n"))
	if len(gpus) != protocol.MaxGPUs || skipped != 8 {
		t.Fatalf("at most %d GPUs: got %d, skipped %d", protocol.MaxGPUs, len(gpus), skipped)
	}
	long, _ := ParseNvidiaSMI("0, GPU-a, " + strings.Repeat("N", 500) + ", 1.0, 1, 1, 1, 1, 1, 1")
	if len(long[0].Name) != protocol.MaxStringLen {
		t.Fatalf("strings must be cut to %d characters, got %d", protocol.MaxStringLen, len(long[0].Name))
	}
}

func TestParseProcFiles(t *testing.T) {
	info := ParseCPUInfo([]byte(cpuinfo))
	if info.Model != "AMD EPYC 7543 32-Core Processor" || info.Logical != 4 || info.PhysicalCores != 2 || !info.Flags["avx"] {
		t.Fatalf("%+v", info)
	}
	total, avail := ParseMemInfo([]byte("MemTotal:       263856568 kB\nMemFree: 1 kB\nMemAvailable:   250000000 kB\n"))
	if *total != 263856568*1024 || *avail != 250000000*1024 {
		t.Fatalf("%d %d", *total, *avail)
	}
	total, avail = ParseMemInfo([]byte("nothing useful"))
	if total != nil || avail != nil {
		t.Fatal("missing values must be nil")
	}
	a, _ := parseProcStat([]byte("cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 1 2 3\n"))
	b, _ := parseProcStat([]byte("cpu  150 0 150 900 0 0 0 0 0 0\n"))
	if util := cpuUtil(a, b); util == nil || *util != 50 {
		t.Fatalf("util = %v", util)
	}
	if util := cpuUtil(b, a); util != nil {
		t.Fatal("a counter going backwards must give null")
	}
	if _, ok := parseProcStat([]byte("garbage")); ok {
		t.Fatal("garbage accepted")
	}
	mounts := ParseMounts([]byte(procMounts))
	if m, ok := MountFor(mounts, "/var/lib/docker/overlay2"); !ok || m.FSType != "xfs" || m.Point != "/var/lib/docker" {
		t.Fatalf("%+v", m)
	}
	if m, _ := MountFor(mounts, "/var/lib/dockerx"); m.Point != "/" {
		t.Fatalf("prefix match must respect path boundaries: %+v", m)
	}
	if m, _ := MountFor(mounts, "/mnt/my disk/x"); m.FSType != "ext4" || m.Point != "/mnt/my disk" {
		t.Fatalf("octal escapes not decoded: %+v", m)
	}
}

const cpuinfo = `processor	: 0
model name	: AMD EPYC 7543 32-Core Processor
physical id	: 0
core id		: 0
flags		: fpu vme avx avx2
processor	: 1
model name	: AMD EPYC 7543 32-Core Processor
physical id	: 0
core id		: 1
flags		: fpu vme avx avx2
processor	: 2
model name	: AMD EPYC 7543 32-Core Processor
physical id	: 0
core id		: 0
flags		: fpu vme avx avx2
processor	: 3
model name	: AMD EPYC 7543 32-Core Processor
physical id	: 0
core id		: 1
flags		: fpu vme avx avx2
`

const procMounts = `/dev/nvme0n1p2 / ext4 rw,relatime 0 0
proc /proc proc rw 0 0
/dev/nvme1n1 /var/lib/docker xfs rw,noatime,prjquota 0 0
/dev/sdb1 /mnt/my\040disk ext4 rw 0 0
`

// fakeRoot builds a minimal host tree.
func fakeRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"/proc/uptime":                          "86400.55 12345.00\n",
		"/proc/cpuinfo":                         cpuinfo,
		"/proc/loadavg":                         "0.42 0.30 0.25 1/1234 5678\n",
		"/proc/stat":                            "cpu  100 0 100 800 0 0 0 0 0 0\n",
		"/proc/meminfo":                         "MemTotal:       263856568 kB\nMemAvailable:   250000000 kB\n",
		"/proc/mounts":                          procMounts,
		"/var/lib/docker/.keep":                 "",
		"/usr/bin/nvidia-smi":                   "#!/bin/false\n",
		"/usr/bin/systemctl":                    "#!/bin/false\n",
		"/var/lib/vastai_kaalia/machine_num_id": "  4242\n",
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func fakeRunner() *execx.Fake {
	f := execx.NewFake()
	f.On(smiLine, execx.FakeResponse{Stdout: "0, GPU-6f0c, NVIDIA GeForce RTX 4090, 550.120, 24564, 12, 0, 34.80, 41, 30\n1, GPU-7a1d, NVIDIA GeForce RTX 4090, 550.120, 24564, 100, 55, [N/A], 60, [N/A]\n"})
	f.On("/usr/bin/systemctl is-active docker.service", execx.FakeResponse{Stdout: "active\n"})
	f.On("/usr/bin/systemctl is-active vastai.service", execx.FakeResponse{Stdout: "failed\n", ExitCode: 3})
	f.On("/usr/bin/systemctl is-active nvidia-persistenced.service", execx.FakeResponse{Stdout: "inactive\n", ExitCode: 3})
	f.On("/usr/bin/systemctl show --property=LoadState --value nvidia-persistenced.service", execx.FakeResponse{Stdout: "not-found\n"})
	return f
}

func newFakeCollector(t *testing.T) (*Real, *execx.Fake, string) {
	root := fakeRoot(t)
	runner := fakeRunner()
	c := &Real{
		Root: root, Runner: runner, ExtraMounts: []string{"/does-not-exist"},
		VastMachineIDFile: "/var/lib/vastai_kaalia/machine_num_id",
		Statfs: func(path string) (uint64, uint64, error) {
			if !strings.HasPrefix(path, root) {
				return 0, 0, errors.New("statfs outside the fake root")
			}
			if strings.HasSuffix(path, "/var/lib/docker") {
				return 2000e9, 1500e9, nil
			}
			return 500e9, 400e9, nil
		},
	}
	return c, runner, root
}

func TestRealCollectorOnFakeRoot(t *testing.T) {
	c, runner, _ := newFakeCollector(t)
	s, warnings := c.Collect(context.Background())
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if *s.UptimeS != 86400 || s.CPU.Model != "AMD EPYC 7543 32-Core Processor" || *s.CPU.Cores != 4 || *s.CPU.Load1 != 0.42 {
		t.Fatalf("cpu/uptime: %+v %v", s.CPU, *s.UptimeS)
	}
	if s.CPU.UtilPct != nil {
		t.Fatal("the first sample has no CPU utilisation yet: it must be null, not 0")
	}
	if *s.Memory.TotalBytes != 263856568*1024 {
		t.Fatalf("memory: %+v", s.Memory)
	}
	if len(s.Disks) != 2 || s.Disks[0].Mount != "/" || s.Disks[0].FS != "ext4" || s.Disks[1].Mount != "/var/lib/docker" ||
		s.Disks[1].FS != "xfs" || *s.Disks[1].TotalBytes != 2000e9 || *s.Disks[1].AvailBytes != 1500e9 {
		t.Fatalf("disks: %+v", s.Disks)
	}
	if len(s.GPUs) != 2 || s.GPUs[1].PowerW != nil || s.GPUs[1].FanPct != nil || *s.GPUs[1].UtilPct != 55 {
		t.Fatalf("gpus: %+v", s.GPUs)
	}
	want := map[string]string{"docker": "active", "vastai": "failed", "nvidia-persistenced": "not-installed"}
	for unit, state := range want {
		if s.Services[unit] != state {
			t.Errorf("service %s = %q, want %q", unit, s.Services[unit], state)
		}
	}
	if !s.Vast.DaemonInstalled {
		t.Fatal("the Vast daemon must be detected")
	}
	// sha256("raw-vast-machine-identifier-123")
	if s.Vast.MachineIDHint == nil || !strings.HasPrefix(*s.Vast.MachineIDHint, "sha256:") || len(*s.Vast.MachineIDHint) != 71 {
		t.Fatalf("hint: %v", s.Vast.MachineIDHint)
	}
	raw, _ := json.Marshal(s)
	if strings.Contains(string(raw), "raw-vast-machine-identifier") {
		t.Fatal("the raw Vast machine identifier must never be sent")
	}
	for _, call := range runner.CallLog() {
		if !strings.HasPrefix(call, "/usr/bin/nvidia-smi --query-gpu=") && !strings.HasPrefix(call, "/usr/bin/systemctl is-active ") &&
			!strings.HasPrefix(call, "/usr/bin/systemctl show --property=LoadState --value ") {
			t.Errorf("unexpected command: %q", call)
		}
	}

	// Second sample: CPU utilisation is the delta.
	if err := os.WriteFile(filepath.Join(c.Root, "proc/stat"), []byte("cpu  150 0 150 900 0 0 0 0 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, _ = c.Collect(context.Background())
	if s.CPU.UtilPct == nil || *s.CPU.UtilPct != 50 {
		t.Fatalf("util: %v", s.CPU.UtilPct)
	}
}

func TestCollectorDegradesToNullsNotZeros(t *testing.T) {
	// An empty root: nothing readable, no nvidia-smi, no systemctl.
	c := &Real{Root: t.TempDir(), Runner: execx.NewFake(), Statfs: func(string) (uint64, uint64, error) { return 0, 0, errors.New("no") },
		VastMachineIDFile: "/var/lib/vastai_kaalia/machine_num_id"}
	s, warnings := c.Collect(context.Background())
	if len(warnings) == 0 {
		t.Fatal("failures must be reported as warnings")
	}
	raw, _ := json.Marshal(s)
	for _, want := range []string{`"uptime_s":null`, `"cores":null`, `"load1":null`, `"util_pct":null`, `"total_bytes":null`,
		`"available_bytes":null`, `"gpus":[]`, `"machine_id_hint":null`, `"daemon_installed":false`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("want %s in %s", want, raw)
		}
	}
	for unit, state := range s.Services {
		if state != protocol.ServiceUnknown {
			t.Errorf("%s = %q, want unknown without systemctl", unit, state)
		}
	}
}

func TestVastHintIsNullWhenUnreadable(t *testing.T) {
	c, _, root := newFakeCollector(t)
	if err := os.Remove(filepath.Join(root, "var/lib/vastai_kaalia/machine_num_id")); err != nil {
		t.Fatal(err)
	}
	s, _ := c.Collect(context.Background())
	if s.Vast.MachineIDHint != nil {
		t.Fatal("no readable identifier: the hint must be null")
	}
	if !s.Vast.DaemonInstalled {
		t.Fatal("the daemon is still installed")
	}
}

func TestNvidiaSMIFailureGivesEmptyList(t *testing.T) {
	c, runner, _ := newFakeCollector(t)
	runner.On(smiLine, execx.FakeResponse{Stdout: "NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver.\n", ExitCode: 9})
	s, warnings := c.Collect(context.Background())
	if len(s.GPUs) != 0 || len(warnings) == 0 {
		t.Fatalf("gpus %v warnings %v", s.GPUs, warnings)
	}
	runner.On(smiLine, execx.FakeResponse{Err: errors.New("timed out")})
	s, _ = c.Collect(context.Background())
	if s.GPUs == nil || len(s.GPUs) != 0 {
		t.Fatal("a timeout must give an empty list")
	}
}

func TestUnitStateMapping(t *testing.T) {
	cases := []struct {
		active, load string
		want         string
	}{
		{"active", "", "active"},
		{"failed", "", "failed"},
		{"activating", "", "activating"},
		{"inactive", "loaded", "inactive"},
		{"inactive", "not-found", "not-installed"},
		{"inactive", "LoadState=not-found", "not-installed"},
		{"unknown", "not-found", "not-installed"},
		{"deactivating", "", "unknown"},
		{"reloading", "", "unknown"},
		{"weird output", "", "unknown"},
	}
	for _, tc := range cases {
		f := execx.NewFake()
		f.On("/usr/bin/systemctl is-active docker.service", execx.FakeResponse{Stdout: tc.active + "\n"})
		f.On("/usr/bin/systemctl show --property=LoadState --value docker.service", execx.FakeResponse{Stdout: tc.load + "\n"})
		if got := UnitState(context.Background(), f, "/usr/bin/systemctl", "docker"); got != tc.want {
			t.Errorf("is-active=%q LoadState=%q: got %q, want %q", tc.active, tc.load, got, tc.want)
		}
	}
	f := execx.NewFake() // nothing registered: the command fails
	if got := UnitState(context.Background(), f, "/usr/bin/systemctl", "docker"); got != "unknown" {
		t.Errorf("a failing systemctl must give unknown, got %q", got)
	}
}

// allowedKeys is the privacy whitelist: exactly the keys of the protocol's
// sample object. Anything else in a serialised sample fails the test.
var allowedKeys = map[string][]string{
	"":         {"seq", "collected_at", "uptime_s", "synthetic", "cpu", "memory", "disks", "gpus", "services", "vast"},
	"cpu":      {"model", "cores", "load1", "util_pct"},
	"memory":   {"total_bytes", "available_bytes"},
	"disks":    {"mount", "fs", "total_bytes", "avail_bytes"},
	"gpus":     {"index", "uuid", "name", "driver_version", "vram_total_mib", "vram_used_mib", "util_pct", "power_w", "temp_c", "fan_pct"},
	"services": {"docker", "vastai", "nvidia-persistenced"},
	"vast":     {"daemon_installed", "machine_id_hint"},
}

func checkKeys(t *testing.T, where string, obj map[string]any) {
	t.Helper()
	allowed := map[string]bool{}
	for _, k := range allowedKeys[where] {
		allowed[k] = true
	}
	for k := range obj {
		if !allowed[k] {
			t.Errorf("key %q under %q is not in the protocol whitelist", k, where)
		}
	}
	for _, k := range allowedKeys[where] {
		if _, ok := obj[k]; !ok && where != "services" {
			t.Errorf("key %q under %q is missing", k, where)
		}
	}
}

func TestSamplePrivacyWhitelist(t *testing.T) {
	c, _, _ := newFakeCollector(t)
	s, _ := c.Collect(context.Background())
	s.Seq, s.CollectedAt = 1, "2026-10-02T07:44:58Z"
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	checkKeys(t, "", top)
	for _, section := range []string{"cpu", "memory", "services", "vast"} {
		checkKeys(t, section, top[section].(map[string]any))
	}
	for _, section := range []string{"disks", "gpus"} {
		list := top[section].([]any)
		if len(list) == 0 {
			t.Fatalf("%s is empty in the test fixture", section)
		}
		for _, item := range list {
			checkKeys(t, section, item.(map[string]any))
		}
	}
	// No key anywhere in the sample may name something workload-related.
	var keys []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				keys = append(keys, strings.ToLower(k))
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(top)
	for _, key := range keys {
		for _, forbidden := range []string{"process", "pid", "cmd", "command", "container", "image", "env", "path", "file", "prompt", "dataset", "user"} {
			if strings.Contains(key, forbidden) {
				t.Errorf("sample key %q looks workload-related (%q)", key, forbidden)
			}
		}
	}
	for _, forbidden := range []string{"docker.sock", "overlay2", "/proc/"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("sample contains %q: %s", forbidden, raw)
		}
	}
}

func TestCollectorOnlyRunsAllowlistedCommands(t *testing.T) {
	c, runner, _ := newFakeCollector(t)
	c.Collect(context.Background())
	for _, call := range runner.CallLog() {
		for _, forbidden := range []string{"docker ", "ps ", "sh ", "bash", "--query-compute-apps", "pmon", "inspect", "exec"} {
			if strings.Contains(call, forbidden) {
				t.Errorf("forbidden command or argument %q in %q", forbidden, call)
			}
		}
	}
	if strings.Contains(strings.Join(NvidiaSMIArgs, " "), "apps") || strings.Contains(strings.Join(NvidiaSMIArgs, " "), "pid") {
		t.Fatal("the nvidia-smi query must not ask for processes")
	}
}

// The Vast daemon's "machine_id" file is its host API key. The collector must
// refuse it even when it is readable and even if someone configures it.
func TestVastKeyFileIsNeverRead(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "var/lib/vastai_kaalia")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("ab", 32)
	if err := os.WriteFile(filepath.Join(dir, "machine_id"), []byte(secret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &Real{Root: root, Runner: execx.NewFake(), VastMachineIDFile: "/var/lib/vastai_kaalia/machine_id",
		Statfs: func(string) (uint64, uint64, error) { return 0, 0, errors.New("no") }}
	if hint := c.vastHint(); hint != nil {
		t.Fatalf("a hint was derived from Vast's key file: %s", *hint)
	}
}

// Only a plain decimal number is treated as the machine id. Anything else,
// such as a 64-hex key written to an unexpected path, yields no hint.
func TestVastHintOnlyFromNumericID(t *testing.T) {
	for content, want := range map[string]bool{
		"4242\n":                 true,
		"  900001  ":             true,
		strings.Repeat("ab", 32): false,
		"12ab":                   false,
		"":                       false,
		"1234567890123":          false,
		"-5":                     false,
	} {
		root := t.TempDir()
		dir := filepath.Join(root, "var/lib/vastai_kaalia")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "machine_num_id"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		c := &Real{Root: root, Runner: execx.NewFake(), VastMachineIDFile: "/var/lib/vastai_kaalia/machine_num_id",
			Statfs: func(string) (uint64, uint64, error) { return 0, 0, errors.New("no") }}
		got := c.vastHint() != nil
		if got != want {
			t.Errorf("content %q: hint present = %v, want %v", content, got, want)
		}
	}
}
