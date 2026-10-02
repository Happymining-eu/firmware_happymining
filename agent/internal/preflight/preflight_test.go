package preflight

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/execx"
)

const smiLine = "/usr/bin/nvidia-smi --query-gpu=index,uuid,name,driver_version,memory.total,memory.used,utilization.gpu,power.draw,temperature.gpu,fan.speed --format=csv,noheader,nounits"

const cpuinfoTmpl = `processor	: 0
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
core id		: 2
flags		: fpu vme avx avx2
processor	: 3
model name	: AMD EPYC 7543 32-Core Processor
physical id	: 0
core id		: 3
flags		: fpu vme avx avx2
`

// host describes a fake machine.
type host struct {
	files   map[string]string
	runner  *execx.Fake
	statfs  map[string][2]uint64 // logical path -> total, avail
	arch    string
	offline bool
	apiErr  error
	netErr  error
}

// goodHost is a machine that meets every verified requirement.
func goodHost() *host {
	h := &host{
		arch: "amd64",
		files: map[string]string{
			"/etc/os-release":                "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n",
			"/proc/cpuinfo":                  cpuinfoTmpl,
			"/proc/meminfo":                  "MemTotal:       65536000 kB\nMemAvailable:   60000000 kB\n",
			"/proc/sys/kernel/osrelease":     "6.8.0-45-generic\n",
			"/proc/mounts":                   "/dev/nvme0n1p2 / ext4 rw 0 0\n/dev/nvme1n1 /var/lib/docker xfs rw 0 0\n",
			"/sys/class/dmi/id/sys_vendor":   "Supermicro\n",
			"/sys/class/dmi/id/product_name": "SYS-4029GP-TRT\n",
			"/var/lib/docker/.keep":          "",
			"/usr/bin/nvidia-smi":            "x",
			"/usr/bin/timedatectl":           "x",
			"/var/lib/dpkg/status":           "Package: docker-ce\nStatus: install ok installed\nVersion: 5:27.0\n\nPackage: vim\nStatus: install ok installed\n\n",
		},
		runner: execx.NewFake(),
		statfs: map[string][2]uint64{
			"/":               {250e9, 120e9},
			"/var/lib/docker": {1000e9, 900e9},
		},
	}
	h.runner.On(smiLine, execx.FakeResponse{Stdout: "0, GPU-a, NVIDIA GeForce RTX 4090, 550.120, 24564, 12, 0, 34.80, 41, 30\n1, GPU-b, NVIDIA GeForce RTX 4090, 550.120, 24564, 12, 0, 34.80, 41, 30\n"})
	h.runner.On("/usr/bin/timedatectl show --property=NTPSynchronized --value", execx.FakeResponse{Stdout: "yes\n"})
	return h
}

func (h *host) run(t *testing.T) Report {
	t.Helper()
	root := t.TempDir()
	for name, content := range h.files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	before := snapshot(t, root)
	env := Env{
		Root: root, Runner: h.runner, Arch: h.arch, Offline: h.offline,
		Statfs: func(path string) (uint64, uint64, error) {
			logical := strings.TrimPrefix(path, root)
			if logical == "" {
				logical = "/"
			}
			v, ok := h.statfs[logical]
			if !ok {
				return 0, 0, errors.New("no such filesystem in the fixture: " + logical)
			}
			return v[0], v[1], nil
		},
		ProbeAPI:   func(context.Context) (string, error) { return "api.example.test answered", h.apiErr },
		ProbeHTTPS: func(context.Context, string) error { return h.netErr },
		Now:        func() time.Time { return time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC) },
	}
	rep := Run(context.Background(), env, EmbeddedRequirements())
	if after := snapshot(t, root); after != before {
		t.Fatalf("preflight changed the host:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	for _, call := range h.runner.CallLog() {
		if !strings.HasPrefix(call, "/usr/bin/nvidia-smi --query-gpu=") && call != "/usr/bin/timedatectl show --property=NTPSynchronized --value" {
			t.Errorf("preflight ran an unexpected command: %q", call)
		}
	}
	return rep
}

// snapshot lists every file with size and mode, to prove read-only behaviour.
func snapshot(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		b.WriteString(strings.TrimPrefix(path, root) + " " + info.Mode().String() + " ")
		if info.Mode().IsRegular() {
			data, _ := os.ReadFile(path)
			b.Write(data)
		}
		b.WriteString("\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func find(t *testing.T, rep Report, id string) Check {
	t.Helper()
	for _, c := range rep.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("check %q not in the report", id)
	return Check{}
}

func TestSupportedHostPasses(t *testing.T) {
	rep := goodHost().run(t)
	for _, id := range []string{"os_release", "architecture", "cpu_features", "virtualization", "gpu_presence", "gpu_vram",
		"gpu_identical", "nvidia_driver", "cpu_cores_per_gpu", "ram_per_gpu", "storage_root_free", "storage_docker_dedicated",
		"storage_docker_size", "network_api", "network_https", "time_sync", "vast_install", "secure_boot"} {
		if c := find(t, rep, id); c.Status != Pass {
			t.Errorf("%s: %s (%s)", id, c.Status, c.Detail)
		}
	}
	if rep.Summary[Fail] != 0 {
		t.Fatalf("a supported host must have no FAIL: %+v", rep.Summary)
	}
	// Checks that depend on unverified thresholds must be WARN with the fixed
	// wording, never PASS or FAIL.
	for _, id := range []string{"storage_docker_fs", "docker_install"} {
		c := find(t, rep, id)
		if c.Status != Warn || !strings.Contains(c.Detail, Unverified) {
			t.Errorf("%s: want WARN %q, got %s (%s)", id, Unverified, c.Status, c.Detail)
		}
	}
	if rep.Overall != Warn {
		t.Fatalf("overall: %s", rep.Overall)
	}
	if c := find(t, rep, "os_release"); !strings.Contains(c.Detail, "ubuntu 24.04") || c.RequirementSource != "https://docs.vast.ai/host/verification-stages" {
		t.Errorf("os check: %+v", c)
	}
	if c := find(t, rep, "not_checked"); c.Status != Skip || !strings.Contains(c.Detail, "500 Mbps") {
		t.Errorf("the report must list what it cannot check: %+v", c)
	}
}

func TestReportStatesThatPassingIsNoGuarantee(t *testing.T) {
	rep := goodHost().run(t)
	var text bytes.Buffer
	Render(&text, rep)
	raw, _ := json.Marshal(rep)
	for name, out := range map[string]string{"table": text.String(), "json": string(raw)} {
		if !strings.Contains(out, "does not guarantee") {
			t.Errorf("%s output lacks the no-guarantee statement", name)
		}
		if !strings.Contains(out, "does not automatically guarantee verification") {
			t.Errorf("%s output lacks Vast's own statement", name)
		}
	}
	if !strings.Contains(text.String(), "STATUS") || !strings.Contains(text.String(), "Overall: WARN") {
		t.Errorf("table:\n%s", text.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	first := decoded["checks"].([]any)[0].(map[string]any)
	for _, key := range []string{"id", "title", "status", "detail", "remediation", "requirement_source"} {
		if _, ok := first[key]; !ok {
			t.Errorf("check JSON lacks %q", key)
		}
	}
}

func TestUnsupportedOSFails(t *testing.T) {
	for name, release := range map[string]string{
		"ubuntu 20.04": "ID=ubuntu\nVERSION_ID=\"20.04\"\n",
		"ubuntu 25.10": "ID=ubuntu\nVERSION_ID=\"25.10\"\n",
		"debian 12":    "ID=debian\nVERSION_ID=\"12\"\n",
		"no version":   "ID=arch\n",
	} {
		h := goodHost()
		h.files["/etc/os-release"] = release
		rep := h.run(t)
		c := find(t, rep, "os_release")
		if c.Status != Fail || c.Remediation == "" || rep.Overall != Fail {
			t.Errorf("%s: %s overall %s (%s)", name, c.Status, rep.Overall, c.Detail)
		}
	}
	h := goodHost()
	delete(h.files, "/etc/os-release")
	if c := find(t, h.run(t), "os_release"); c.Status != Fail {
		t.Errorf("missing os-release: %s", c.Status)
	}
	h = goodHost()
	h.files["/etc/os-release"] = "ID=ubuntu\nVERSION_ID=\"22.04\"\n"
	if c := find(t, h.run(t), "os_release"); c.Status != Pass {
		t.Errorf("ubuntu 22.04 must pass: %s", c.Detail)
	}
}

func TestSnapDockerFails(t *testing.T) {
	h := goodHost()
	h.files["/var/lib/dpkg/status"] = "Package: vim\nStatus: install ok installed\n\n"
	h.files["/snap/bin/docker"] = "x"
	rep := h.run(t)
	c := find(t, rep, "docker_install")
	if c.Status != Fail || !strings.Contains(c.Detail, "snap") || !strings.Contains(c.Remediation, "never install, remove or replace") {
		t.Fatalf("%+v", c)
	}
	if rep.Overall != Fail {
		t.Fatalf("overall %s", rep.Overall)
	}
}

func TestCoexistingDockerInstallsFail(t *testing.T) {
	h := goodHost()
	h.files["/snap/bin/docker"] = "x" // docker-ce deb + snap
	c := find(t, h.run(t), "docker_install")
	if c.Status != Fail || !strings.Contains(c.Detail, "coexist") || !strings.Contains(c.Detail, "docker-ce") {
		t.Fatalf("%+v", c)
	}
}

func TestDockerVariants(t *testing.T) {
	h := goodHost()
	h.files["/var/lib/dpkg/status"] = "Package: docker.io\nStatus: install ok installed\n\n"
	if c := find(t, h.run(t), "docker_install"); c.Status != Warn || !strings.Contains(c.Detail, "docker.io") {
		t.Errorf("docker.io: %+v", c)
	}
	// Removed but not purged: not installed.
	h = goodHost()
	h.files["/var/lib/dpkg/status"] = "Package: docker-ce\nStatus: deinstall ok config-files\n\n"
	if c := find(t, h.run(t), "docker_install"); c.Status != Pass || !strings.Contains(c.Detail, "no Docker installation") {
		t.Errorf("config-files state: %+v", c)
	}
	h = goodHost()
	h.files["/var/lib/dpkg/status"] = ""
	h.files["/usr/bin/dockerd"] = "x"
	if c := find(t, h.run(t), "docker_install"); c.Status != Warn {
		t.Errorf("unknown binary: %+v", c)
	}
}

func TestExistingVastInstallIsReportedAndPreserved(t *testing.T) {
	h := goodHost()
	h.files["/etc/systemd/system/vastai.service"] = "[Unit]\nDescription=fixture\n"
	h.files["/var/lib/vastai_kaalia/machine_id"] = "fixture-id\n"
	rep := h.run(t) // run() also proves that no file was modified or removed
	c := find(t, rep, "vast_install")
	if c.Status != Pass || !strings.Contains(c.Detail, "/etc/systemd/system/vastai.service") || !strings.Contains(c.Detail, "preserved") {
		t.Fatalf("%+v", c)
	}
	if strings.Contains(c.Detail, "fixture-id") {
		t.Fatal("the report must not contain the Vast machine identifier")
	}
	none := find(t, goodHost().run(t), "vast_install")
	if !strings.Contains(none.Detail, "not found") || !strings.Contains(none.Detail, "vast-enroll-help") {
		t.Fatalf("%+v", none)
	}
}

func TestMissingGPUFails(t *testing.T) {
	h := goodHost()
	delete(h.files, "/usr/bin/nvidia-smi")
	rep := h.run(t)
	if c := find(t, rep, "gpu_presence"); c.Status != Fail || !strings.Contains(c.Detail, "no NVIDIA GPU") {
		t.Fatalf("%+v", c)
	}
	for _, id := range []string{"gpu_vram", "gpu_identical", "nvidia_driver", "cpu_cores_per_gpu", "ram_per_gpu"} {
		if c := find(t, rep, id); c.Status != Skip {
			t.Errorf("%s: %s", id, c.Status)
		}
	}
	if rep.Overall != Fail {
		t.Fatalf("overall %s", rep.Overall)
	}
}

func TestGPUOnPCIBusWithoutDriver(t *testing.T) {
	h := goodHost()
	delete(h.files, "/usr/bin/nvidia-smi")
	h.files["/sys/bus/pci/devices/0000:01:00.0/vendor"] = "0x10de\n"
	h.files["/sys/bus/pci/devices/0000:01:00.0/class"] = "0x030000\n"
	h.files["/sys/bus/pci/devices/0000:01:00.1/vendor"] = "0x10de\n" // HDMI audio function: not a GPU
	h.files["/sys/bus/pci/devices/0000:01:00.1/class"] = "0x040300\n"
	h.files["/sys/bus/pci/devices/0000:02:00.0/vendor"] = "0x8086\n"
	h.files["/sys/bus/pci/devices/0000:02:00.0/class"] = "0x030000\n"
	c := find(t, h.run(t), "gpu_presence")
	if c.Status != Warn || !strings.Contains(c.Detail, "1 NVIDIA display device") {
		t.Fatalf("%+v", c)
	}
}

func TestDriverInstalledButBroken(t *testing.T) {
	h := goodHost()
	h.runner.On(smiLine, execx.FakeResponse{ExitCode: 9, Stdout: "NVIDIA-SMI has failed\n"})
	if c := find(t, h.run(t), "gpu_presence"); c.Status != Fail || !strings.Contains(c.Detail, "nvidia-smi is installed") {
		t.Fatalf("%+v", c)
	}
}

func TestHardwareThresholds(t *testing.T) {
	// Too little VRAM, mixed models, old driver.
	h := goodHost()
	h.runner.On(smiLine, execx.FakeResponse{Stdout: "0, GPU-a, NVIDIA GeForce GTX 1060 6GB, 470.82, 6144, 1, 0, 10, 40, 30\n1, GPU-b, NVIDIA GeForce RTX 4090, 470.82, 24564, 1, 0, 10, 40, 30\n"})
	rep := h.run(t)
	if c := find(t, rep, "gpu_vram"); c.Status != Fail || !strings.Contains(c.Detail, "GPU 0: 6144 MiB") {
		t.Errorf("vram: %+v", c)
	}
	if c := find(t, rep, "gpu_identical"); c.Status != Fail {
		t.Errorf("identical: %+v", c)
	}
	if c := find(t, rep, "nvidia_driver"); c.Status != Fail || !strings.Contains(c.Detail, "520.61.05") {
		t.Errorf("driver: %+v", c)
	}

	// 8 GPUs on 4 physical cores and 62.5 GiB of RAM.
	h = goodHost()
	var lines []string
	for i := 0; i < 8; i++ {
		lines = append(lines, string(rune('0'+i))+", GPU-x, NVIDIA GeForce RTX 4090, 550.120, 24564, 1, 0, 10, 40, 30")
	}
	h.runner.On(smiLine, execx.FakeResponse{Stdout: strings.Join(lines, "\n")})
	rep = h.run(t)
	if c := find(t, rep, "cpu_cores_per_gpu"); c.Status != Fail || !strings.Contains(c.Detail, "16 needed") {
		t.Errorf("cores: %+v", c)
	}
	if c := find(t, rep, "ram_per_gpu"); c.Status != Fail {
		t.Errorf("ram: %+v", c)
	}

	// Unknown VRAM must not be treated as 0.
	h = goodHost()
	h.runner.On(smiLine, execx.FakeResponse{Stdout: "0, GPU-a, NVIDIA GeForce RTX 4090, 550.120, [N/A], 1, 0, 10, 40, 30\n"})
	rep = h.run(t)
	if c := find(t, rep, "gpu_vram"); c.Status != Warn {
		t.Errorf("unknown vram: %+v", c)
	}
	if c := find(t, rep, "ram_per_gpu"); c.Status != Skip {
		t.Errorf("ram with unknown vram: %+v", c)
	}
}

func TestStorageChecks(t *testing.T) {
	// Docker on the root filesystem: not a dedicated drive.
	h := goodHost()
	h.files["/proc/mounts"] = "/dev/nvme0n1p2 / ext4 rw 0 0\n"
	h.statfs["/var/lib/docker"] = h.statfs["/"]
	rep := h.run(t)
	if c := find(t, rep, "storage_docker_dedicated"); c.Status != Fail || !strings.Contains(c.Remediation, "never repartition") {
		t.Errorf("dedicated: %+v", c)
	}
	// Small Docker filesystem and nearly full root.
	h = goodHost()
	h.statfs["/var/lib/docker"] = [2]uint64{100e9, 90e9}
	h.statfs["/"] = [2]uint64{50e9, 5e9}
	rep = h.run(t)
	if c := find(t, rep, "storage_docker_size"); c.Status != Fail {
		t.Errorf("size: %+v", c)
	}
	if c := find(t, rep, "storage_root_free"); c.Status != Fail || !strings.Contains(c.Remediation, "Never delete renter data") {
		t.Errorf("root free: %+v", c)
	}
	// Just under 200 GB: filesystem overhead, WARN rather than FAIL.
	h = goodHost()
	h.statfs["/var/lib/docker"] = [2]uint64{197e9, 190e9}
	if c := find(t, h.run(t), "storage_docker_size"); c.Status != Warn {
		t.Errorf("just under: %+v", c)
	}
	// Docker not installed yet: judged by the nearest existing directory,
	// and data-root from daemon.json is honoured.
	h = goodHost()
	delete(h.files, "/var/lib/docker/.keep")
	h.files["/etc/docker/daemon.json"] = `{"data-root": "/data/docker"}`
	h.files["/data/.keep"] = ""
	h.files["/proc/mounts"] = "/dev/nvme0n1p2 / ext4 rw 0 0\n/dev/nvme1n1 /data xfs rw 0 0\n"
	h.statfs["/data"] = [2]uint64{2000e9, 1900e9}
	rep = h.run(t)
	if c := find(t, rep, "storage_docker_dedicated"); c.Status != Pass || !strings.Contains(c.Detail, "/data/docker") {
		t.Errorf("data-root: %+v", c)
	}
	if c := find(t, rep, "storage_docker_size"); c.Status != Pass {
		t.Errorf("data-root size: %+v", c)
	}
}

func TestSecureBootVirtualizationTimeAndNetwork(t *testing.T) {
	h := goodHost()
	h.files["/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"] = "\x06\x00\x00\x00\x01"
	h.files["/sys/class/dmi/id/sys_vendor"] = "QEMU\n"
	h.runner.On("/usr/bin/timedatectl show --property=NTPSynchronized --value", execx.FakeResponse{Stdout: "no\n"})
	h.apiErr = errors.New("dial tcp: connection refused")
	h.netErr = errors.New("x509: certificate has expired")
	rep := h.run(t)
	if c := find(t, rep, "secure_boot"); c.Status != Fail || !strings.Contains(c.Remediation, "reboot") {
		t.Errorf("secure boot: %+v", c)
	}
	if c := find(t, rep, "virtualization"); c.Status != Warn {
		t.Errorf("virtualization: %+v", c)
	}
	if c := find(t, rep, "time_sync"); c.Status != Warn {
		t.Errorf("time: %+v", c)
	}
	if c := find(t, rep, "network_api"); c.Status != Fail || !strings.Contains(c.Remediation, "does not stop Vast hosting") {
		t.Errorf("api: %+v", c)
	}
	if c := find(t, rep, "network_https"); c.Status != Fail {
		t.Errorf("https: %+v", c)
	}

	h = goodHost()
	h.files["/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"] = "\x06\x00\x00\x00\x00"
	if c := find(t, h.run(t), "secure_boot"); c.Status != Pass || !strings.Contains(c.Detail, "disabled") {
		t.Errorf("secure boot off: %+v", c)
	}
}

func TestOfflineSkipsNetworkChecks(t *testing.T) {
	h := goodHost()
	h.offline = true
	h.apiErr = errors.New("must not be called")
	rep := h.run(t)
	for _, id := range []string{"network_api", "network_https"} {
		if c := find(t, rep, id); c.Status != Skip {
			t.Errorf("%s: %s", id, c.Status)
		}
	}
}

func TestArchitecture(t *testing.T) {
	h := goodHost()
	h.arch = "arm64"
	if c := find(t, h.run(t), "architecture"); c.Status != Warn {
		t.Errorf("arm64: %+v", c)
	}
	h = goodHost()
	h.arch = "riscv64"
	if c := find(t, h.run(t), "architecture"); c.Status != Fail {
		t.Errorf("riscv64: %+v", c)
	}
	h = goodHost()
	h.files["/proc/cpuinfo"] = strings.ReplaceAll(cpuinfoTmpl, " avx avx2", "")
	if c := find(t, h.run(t), "cpu_features"); c.Status != Fail {
		t.Errorf("no avx: %+v", c)
	}
}

func TestEmbeddedRequirementsAreWellFormed(t *testing.T) {
	var generic map[string]any
	if err := json.Unmarshal(embeddedRequirements, &generic); err != nil {
		t.Fatal(err)
	}
	official := regexp.MustCompile(`^https://(docs\.vast\.ai|cloud\.vast\.ai|docs\.nvidia\.com)/`)
	thresholds := 0
	for key, v := range generic {
		obj, ok := v.(map[string]any)
		if !ok {
			continue
		}
		thresholds++
		source, _ := obj["source"].(string)
		verified, hasVerified := obj["verified"].(bool)
		if !hasVerified {
			t.Errorf("%s: no verified boolean", key)
		}
		if !official.MatchString(source) {
			t.Errorf("%s: source %q is not an official Vast or NVIDIA URL", key, source)
		}
		if _, ok := obj["value"]; !ok {
			t.Errorf("%s: no value", key)
		}
		if quote, _ := obj["quote"].(string); verified && quote == "" {
			t.Errorf("%s: a verified threshold must record what was read", key)
		}
	}
	if thresholds < 15 {
		t.Fatalf("only %d thresholds found", thresholds)
	}
	req := EmbeddedRequirements()
	if req.DockerStorageFS.Verified || req.DockerPackagesExpected.Verified || req.VastDetectionPaths.Verified {
		t.Fatal("these thresholds were not read on an official page and must stay unverified")
	}
	for _, u := range req.OutboundHTTPSProbes {
		if strings.Contains(u, "vast.ai") {
			t.Errorf("preflight must not contact Vast: %s", u)
		}
	}
}

func TestRequirementsOverride(t *testing.T) {
	var generic map[string]any
	_ = json.Unmarshal(embeddedRequirements, &generic)
	generic["os_releases"].(map[string]any)["value"] = []any{map[string]any{"id": "debian", "version_id": "12"}}
	generic["docker_storage_filesystems"].(map[string]any)["verified"] = true
	raw, _ := json.Marshal(generic)
	path := filepath.Join(t.TempDir(), "req.json")
	_ = os.WriteFile(path, raw, 0o644)
	req, err := LoadRequirements(path)
	if err != nil {
		t.Fatal(err)
	}
	if req.OSReleases.Value[0].ID != "debian" || !req.DockerStorageFS.Verified {
		t.Fatalf("override not applied: %+v", req.OSReleases)
	}
	for name, content := range map[string]string{
		"unknown field": `{"schema_version":1,"surprise":true}`,
		"wrong schema":  `{"schema_version":2}`,
		"not json":      `nope`,
		"empty lists":   `{"schema_version":1}`,
	} {
		_ = os.WriteFile(path, []byte(content), 0o644)
		if _, err := LoadRequirements(path); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := LoadRequirements(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file: expected an error")
	}
}

func TestVerifiedThresholdGivesPassOrFail(t *testing.T) {
	// With the filesystem threshold marked verified the same host gets a real
	// verdict instead of the "not verified" WARN.
	req := EmbeddedRequirements()
	req.DockerStorageFS.Verified = true
	status, detail := gate(req.DockerStorageFS, Pass, "filesystem type xfs")
	if status != Pass || strings.Contains(detail, Unverified) {
		t.Fatalf("%s %s", status, detail)
	}
	req.DockerStorageFS.Verified = false
	for _, decided := range []string{Pass, Fail} {
		status, detail = gate(req.DockerStorageFS, decided, "filesystem type ext4")
		if status != Warn || !strings.HasPrefix(detail, Unverified) {
			t.Fatalf("%s: %s %s", decided, status, detail)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"550.120", "520.61.05", 1}, {"520.61.05", "520.61.05", 0}, {"470.82", "520.61.05", -1},
		{"520.61", "520.61.05", -1}, {"535.183.01", "535.54.03", 1}, {"560", "559.999", 1},
	}
	for _, c := range cases {
		if got, ok := CompareVersions(c.a, c.b); !ok || got != c.want {
			t.Errorf("CompareVersions(%s, %s) = %d, %v; want %d", c.a, c.b, got, ok, c.want)
		}
	}
	for _, bad := range []string{"", "abc", "550.x", "550..1"} {
		if _, ok := CompareVersions(bad, "520"); ok {
			t.Errorf("%q must not compare", bad)
		}
	}
}
