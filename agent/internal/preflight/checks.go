package preflight

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/collector"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/execx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
)

const (
	gb  = 1000 * 1000 * 1000
	gib = 1024 * 1024 * 1024
	mib = 1024 * 1024
)

// neverBlind is appended to every remediation that could tempt an operator
// into a disruptive change.
const neverBlind = " Plan it in a maintenance window with no active rentals and no stored customer data; HappyMining tools never repartition, reinstall or reboot a machine on their own."

func (r *runner) path(p string) string { return filepath.Join(r.env.Root, p) }

func (r *runner) read(p string, limit int64) ([]byte, error) {
	f, err := os.Open(r.path(p))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

func (r *runner) exists(p string) bool {
	_, err := os.Lstat(r.path(p))
	return err == nil
}

// ParseOSRelease parses /etc/os-release.
func ParseOSRelease(data []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(key, "#") {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		out[key] = value
	}
	return out
}

func (r *runner) checkOS() {
	th := r.req.OSReleases
	c := Check{ID: "os_release", Title: "Operating system", RequirementSource: th.Source}
	var names []string
	for _, rel := range th.Value {
		names = append(names, rel.ID+" "+rel.VersionID)
	}
	data, err := r.read("/etc/os-release", 64*1024)
	if err != nil {
		c.Status, c.Detail = Fail, "cannot read /etc/os-release"
		c.Remediation = "Supported releases: " + strings.Join(names, ", ") + "."
		r.add(c)
		return
	}
	kv := ParseOSRelease(data)
	id, ver := kv["ID"], kv["VERSION_ID"]
	supported := false
	for _, rel := range th.Value {
		if rel.ID == id && rel.VersionID == ver {
			supported = true
		}
	}
	found := protocol.Truncate(id+" "+ver, 64)
	if supported {
		c.Status, c.Detail = gate(th, Pass, found+" is a supported release")
	} else {
		c.Status, c.Detail = gate(th, Fail, found+" is not a supported release (supported: "+strings.Join(names, ", ")+")")
		c.Remediation = "Use one of: " + strings.Join(names, ", ") + ". Do not upgrade or reinstall the operating system of a machine that is hosting." + neverBlind
	}
	r.add(c)
}

func (r *runner) checkArch() {
	th := r.req.CPUArchitectures
	c := Check{ID: "architecture", Title: "CPU architecture", RequirementSource: th.Source}
	arch := r.env.Arch
	listed := false
	for _, a := range th.Value {
		if a == arch {
			listed = true
		}
	}
	switch {
	case arch == "amd64" && listed:
		c.Status, c.Detail = gate(th, Pass, "amd64 (x86_64)")
	case listed:
		c.Status = Warn
		c.Detail = arch + " is listed by Vast, but HappyMining OS and this agent package are built for amd64 only"
		c.Remediation = "Use an x86_64 machine for HappyMining OS."
	default:
		c.Status, c.Detail = gate(th, Fail, arch+" is not a supported architecture")
		c.Remediation = "Use an x86_64 machine."
	}
	r.add(c)
}

func (r *runner) checkCPUFlags() collector.CPUInfo {
	th := r.req.CPUFlags
	c := Check{ID: "cpu_features", Title: "CPU instruction set", RequirementSource: th.Source}
	data, err := r.read("/proc/cpuinfo", 8*1024*1024)
	if err != nil {
		c.Status, c.Detail = Skip, "cannot read /proc/cpuinfo"
		r.add(c)
		return collector.CPUInfo{}
	}
	info := collector.ParseCPUInfo(data)
	if r.env.Arch != "amd64" {
		c.Status, c.Detail = Skip, "instruction-set check applies to x86_64 only"
		r.add(c)
		return info
	}
	var missing []string
	for _, f := range th.Value {
		if !info.Flags[f] {
			missing = append(missing, f)
		}
	}
	if len(missing) == 0 {
		c.Status, c.Detail = gate(th, Pass, "required CPU flags present: "+strings.Join(th.Value, ", "))
	} else {
		c.Status, c.Detail = gate(th, Fail, "missing CPU flags: "+strings.Join(missing, ", "))
		c.Remediation = "This CPU lacks a required instruction set; it cannot be fixed in software."
	}
	r.add(c)
	return info
}

func (r *runner) checkKernel() {
	c := Check{ID: "kernel", Title: "Kernel", Status: Skip}
	data, err := r.read("/proc/sys/kernel/osrelease", 256)
	if err != nil {
		c.Detail = "cannot read the kernel release"
		r.add(c)
		return
	}
	c.Detail = "running " + protocol.Truncate(strings.TrimSpace(string(data)), 64) +
		"; whether this is the latest security patch level of the release cannot be decided offline (see the not-checked list)"
	r.add(c)
}

func (r *runner) checkVirtualization(cpu collector.CPUInfo) {
	c := Check{ID: "virtualization", Title: "Virtualization"}
	var hints []string
	if cpu.Flags["hypervisor"] {
		hints = append(hints, "CPU flag 'hypervisor'")
	}
	for _, f := range []string{"/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/product_name"} {
		data, err := r.read(f, 256)
		if err != nil {
			continue
		}
		v := strings.ToLower(strings.TrimSpace(string(data)))
		for _, marker := range []string{"qemu", "kvm", "vmware", "virtualbox", "xen", "microsoft corporation", "bochs", "parallels", "amazon ec2", "google compute"} {
			if strings.Contains(v, marker) {
				hints = append(hints, "DMI "+filepath.Base(f)+" contains '"+marker+"'")
			}
		}
	}
	if data, err := r.read("/sys/hypervisor/type", 64); err == nil && strings.TrimSpace(string(data)) != "" {
		hints = append(hints, "/sys/hypervisor/type is set")
	}
	if len(hints) == 0 {
		c.Status, c.Detail = Pass, "no sign of a virtual machine"
	} else {
		c.Status = Warn
		c.Detail = "this looks like a virtual machine (" + strings.Join(hints, "; ") + ")"
		c.Remediation = "The other checks describe the virtual hardware. Preflight cannot tell whether Vast accepts this setup; run it on the physical host if there is one."
	}
	r.add(c)
}

// nvidiaPCIDevices counts NVIDIA display controllers in sysfs (vendor 0x10de,
// PCI class 0x03xxxx). It needs neither lspci nor a driver.
func (r *runner) nvidiaPCIDevices() int {
	entries, err := os.ReadDir(r.path("/sys/bus/pci/devices"))
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		base := filepath.Join("/sys/bus/pci/devices", e.Name())
		vendor, err := r.read(filepath.Join(base, "vendor"), 32)
		if err != nil || strings.TrimSpace(string(vendor)) != "0x10de" {
			continue
		}
		class, err := r.read(filepath.Join(base, "class"), 32)
		if err != nil || !strings.HasPrefix(strings.TrimSpace(string(class)), "0x03") {
			continue
		}
		n++
	}
	return n
}

func (r *runner) checkGPUs(ctx context.Context) []protocol.GPU {
	presence := Check{ID: "gpu_presence", Title: "NVIDIA GPU"}
	vram := Check{ID: "gpu_vram", Title: "VRAM per GPU", RequirementSource: r.req.MinVRAMPerGPUMiBExcl.Source}
	same := Check{ID: "gpu_identical", Title: "Identical GPU models", RequirementSource: r.req.IdenticalGPUModels.Source}
	driverHelp := "Install an NVIDIA driver release that NVIDIA currently supports for this GPU. HappyMining does not install or change drivers automatically." + neverBlind

	pci := r.nvidiaPCIDevices()
	var gpus []protocol.GPU
	_, findErr := execx.FindAbs(r.env.Root, collector.NvidiaSMICandidates...)
	if findErr == nil {
		var warn []string
		gpus = r.coll.GPUs(ctx, &warn)
		if len(gpus) == 0 && len(warn) > 0 {
			presence.Detail = "nvidia-smi is installed but did not report any GPU (" + protocol.Truncate(strings.Join(warn, "; "), 200) + ")"
		}
	}
	switch {
	case len(gpus) > 0:
		names := map[string]int{}
		var order []string
		for _, g := range gpus {
			if names[g.Name] == 0 {
				order = append(order, g.Name)
			}
			names[g.Name]++
		}
		var parts []string
		for _, n := range order {
			parts = append(parts, fmt.Sprintf("%d x %s", names[n], n))
		}
		presence.Status, presence.Detail = Pass, fmt.Sprintf("%d GPU(s): %s", len(gpus), strings.Join(parts, ", "))
	case findErr == nil:
		presence.Status = Fail
		if presence.Detail == "" {
			presence.Detail = "nvidia-smi is installed but reports no GPU"
		}
		if pci > 0 {
			presence.Detail += fmt.Sprintf("; %d NVIDIA display device(s) are visible on the PCI bus", pci)
		}
		presence.Remediation = driverHelp
	case pci > 0:
		presence.Status = Warn
		presence.Detail = fmt.Sprintf("%d NVIDIA display device(s) on the PCI bus, but nvidia-smi is not installed: model, VRAM and driver cannot be checked", pci)
		presence.Remediation = driverHelp
	default:
		presence.Status = Fail
		presence.Detail = "no NVIDIA GPU detected (no nvidia-smi and no NVIDIA display device on the PCI bus)"
		presence.Remediation = "This machine cannot be hosted without an NVIDIA GPU."
	}
	r.add(presence)

	if len(gpus) == 0 {
		vram.Status, vram.Detail = Skip, "no GPU information"
		same.Status, same.Detail = Skip, "no GPU information"
		r.add(vram)
		r.add(same)
		return gpus
	}

	th := r.req.MinVRAMPerGPUMiBExcl
	var small, unknown []string
	for _, g := range gpus {
		switch {
		case g.VRAMTotalMiB == nil:
			unknown = append(unknown, strconv.Itoa(g.Index))
		case *g.VRAMTotalMiB <= th.Value:
			small = append(small, fmt.Sprintf("GPU %d: %d MiB", g.Index, *g.VRAMTotalMiB))
		}
	}
	switch {
	case len(small) > 0:
		vram.Status, vram.Detail = gate(th, Fail, fmt.Sprintf("needs more than %d MiB per GPU; %s", th.Value, strings.Join(small, ", ")))
		vram.Remediation = "GPUs below the VRAM minimum are not eligible; this cannot be fixed in software."
	case len(unknown) > 0:
		vram.Status, vram.Detail = Warn, "VRAM size unknown for GPU "+strings.Join(unknown, ", ")
		vram.Remediation = "Check the driver installation: nvidia-smi did not report memory.total."
	default:
		vram.Status, vram.Detail = gate(th, Pass, fmt.Sprintf("every GPU has more than %d MiB", th.Value))
	}
	r.add(vram)

	models := map[string]bool{}
	for _, g := range gpus {
		models[g.Name] = true
	}
	ith := r.req.IdenticalGPUModels
	if !ith.Value || len(models) == 1 {
		same.Status, same.Detail = gate(ith, Pass, "all GPUs are the same model")
	} else {
		same.Status, same.Detail = gate(ith, Fail, fmt.Sprintf("%d different GPU models in one machine", len(models)))
		same.Remediation = "Vast asks for identical GPU models in one machine. Moving cards between machines is a hardware change." + neverBlind
	}
	r.add(same)
	return gpus
}

// CompareVersions compares dotted numeric versions (550.120 vs 520.61.05).
func CompareVersions(a, b string) (int, bool) {
	pa, oka := versionParts(a)
	pb, okb := versionParts(b)
	if !oka || !okb {
		return 0, false
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func versionParts(v string) ([]int, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, false
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

func (r *runner) checkDriver(gpus []protocol.GPU) {
	lo, hi := r.req.NvidiaDriverMin, r.req.NvidiaDriverMaxExcl
	c := Check{ID: "nvidia_driver", Title: "NVIDIA driver version", RequirementSource: lo.Source}
	version := ""
	for _, g := range gpus {
		if g.DriverVersion != "" {
			version = g.DriverVersion
			break
		}
	}
	if version == "" {
		c.Status, c.Detail = Skip, "driver version unknown (nvidia-smi did not report it)"
		r.add(c)
		return
	}
	cmp, ok := CompareVersions(version, lo.Value)
	if !ok {
		c.Status, c.Detail = Warn, "driver version "+protocol.Truncate(version, 32)+" could not be compared with the minimum "+lo.Value
		r.add(c)
		return
	}
	suffix := "; Vast also asks for a release NVIDIA currently supports for the GPU, which is not checked"
	if cmp < 0 {
		c.Status, c.Detail = gate(lo, Fail, "driver "+version+" is older than the minimum "+lo.Value)
		c.Remediation = "Install an NVIDIA driver release that NVIDIA currently supports for this GPU (at least " + lo.Value + "). HappyMining does not change drivers automatically." + neverBlind
		r.add(c)
		return
	}
	if hi.Value != "" {
		if cmpHi, ok := CompareVersions(version, hi.Value); ok && cmpHi >= 0 {
			c.RequirementSource = hi.Source
			c.Status, c.Detail = gate(hi, Fail, "driver "+version+" is not below the upper bound "+hi.Value)
			c.Remediation = "Use a driver release inside the supported range." + neverBlind
			r.add(c)
			return
		}
	}
	c.Status, c.Detail = gate(lo, Pass, "driver "+version+" is at least "+lo.Value+suffix)
	r.add(c)
}

func (r *runner) checkCores(cpu collector.CPUInfo, gpus []protocol.GPU) {
	th := r.req.PhysicalCoresPerGPU
	c := Check{ID: "cpu_cores_per_gpu", Title: "CPU cores per GPU", RequirementSource: th.Source}
	if len(gpus) == 0 {
		c.Status, c.Detail = Skip, "no GPU information"
		r.add(c)
		return
	}
	need := int(math.Ceil(th.Value * float64(len(gpus))))
	if cpu.PhysicalCores == 0 {
		c.Status = Warn
		c.Detail = fmt.Sprintf("physical core count unknown (CPU topology not exposed); %d logical CPUs, %d physical cores needed for %d GPU(s)",
			cpu.Logical, need, len(gpus))
		c.Remediation = "Check the physical core count by hand (lscpu)."
		r.add(c)
		return
	}
	detail := fmt.Sprintf("%d physical cores for %d GPU(s), %d needed", cpu.PhysicalCores, len(gpus), need)
	if cpu.PhysicalCores >= need {
		c.Status, c.Detail = gate(th, Pass, detail)
	} else {
		c.Status, c.Detail = gate(th, Fail, detail)
		c.Remediation = "Use a CPU with more physical cores or fewer GPUs in this machine."
	}
	r.add(c)
}

func (r *runner) checkRAM(gpus []protocol.GPU) {
	th := r.req.RAMToTotalVRAMRatio
	c := Check{ID: "ram_per_gpu", Title: "System RAM vs GPU VRAM", RequirementSource: th.Source}
	if len(gpus) == 0 {
		c.Status, c.Detail = Skip, "no GPU information"
		r.add(c)
		return
	}
	var vramMiB int64
	for _, g := range gpus {
		if g.VRAMTotalMiB == nil {
			c.Status, c.Detail = Skip, "VRAM size unknown for at least one GPU"
			r.add(c)
			return
		}
		vramMiB += *g.VRAMTotalMiB
	}
	data, err := r.read("/proc/meminfo", 64*1024)
	total, _ := collector.ParseMemInfo(data)
	if err != nil || total == nil {
		c.Status, c.Detail = Skip, "cannot read MemTotal from /proc/meminfo"
		r.add(c)
		return
	}
	need := th.Value * float64(vramMiB) * mib
	detail := fmt.Sprintf("system RAM %.1f GiB, total VRAM %.1f GiB, at least %.1f GiB needed",
		float64(*total)/gib, float64(vramMiB)*mib/gib, need/gib)
	if float64(*total) >= need {
		c.Status, c.Detail = gate(th, Pass, detail)
	} else {
		c.Status, c.Detail = gate(th, Fail, detail)
		c.Remediation = "Add system memory or host fewer GPUs in this machine."
	}
	r.add(c)
}

// dockerDataRoot returns Docker's data directory: "data-root" from
// /etc/docker/daemon.json when set, otherwise /var/lib/docker. Read-only.
func (r *runner) dockerDataRoot() string {
	data, err := r.read("/etc/docker/daemon.json", 1024*1024)
	if err == nil {
		var cfg struct {
			DataRoot string `json:"data-root"`
		}
		if json.Unmarshal(data, &cfg) == nil && filepath.IsAbs(cfg.DataRoot) {
			return filepath.Clean(cfg.DataRoot)
		}
	}
	return "/var/lib/docker"
}

func (r *runner) checkStorage() {
	rootTh := r.req.RootFreeMinGB
	rootFree := Check{ID: "storage_root_free", Title: "Root filesystem free space", RequirementSource: rootTh.Source}
	if _, avail, err := r.env.Statfs(r.path("/")); err != nil {
		rootFree.Status, rootFree.Detail = Skip, "cannot stat the root filesystem"
	} else {
		detail := fmt.Sprintf("%.1f GB free, %d GB needed", float64(avail)/gb, rootTh.Value)
		if avail >= uint64(rootTh.Value)*gb {
			rootFree.Status, rootFree.Detail = gate(rootTh, Pass, detail)
		} else {
			rootFree.Status, rootFree.Detail = gate(rootTh, Fail, detail)
			rootFree.Remediation = "Free space on the root filesystem (old kernels, logs, package caches). Never delete renter data or Docker storage to make room."
		}
	}
	r.add(rootFree)

	dockerDir := r.dockerDataRoot()
	existing := dockerDir
	for existing != "/" && !r.exists(existing) {
		existing = filepath.Dir(existing)
	}
	where := dockerDir
	if existing != dockerDir {
		where += " (does not exist yet; judged by " + existing + ")"
	}
	var mount collector.Mount
	haveMount := false
	if data, err := r.read("/proc/mounts", 1024*1024); err == nil {
		mount, haveMount = collector.MountFor(collector.ParseMounts(data), existing)
	}

	dedTh := r.req.DockerStorageDedicated
	ded := Check{ID: "storage_docker_dedicated", Title: "Docker storage on its own drive", RequirementSource: dedTh.Source}
	dedHelp := "Vast asks for a dedicated drive for Docker container storage. Prepare it before installing the Vast host software. Moving Docker's data directory later can destroy or strand renter data." + neverBlind
	switch {
	case !haveMount:
		ded.Status, ded.Detail = Skip, "cannot determine the mount of "+where
	case mount.Point == "/":
		ded.Status, ded.Detail = gate(dedTh, Fail, where+" is on the root filesystem, so it is not a dedicated drive")
		ded.Remediation = dedHelp
	default:
		ded.Status, ded.Detail = gate(dedTh, Pass, where+" is on a separate mount ("+mount.Point+"); preflight cannot tell whether that is a dedicated drive")
	}
	r.add(ded)

	sizeTh := r.req.DockerStorageMinGB
	size := Check{ID: "storage_docker_size", Title: "Docker storage size", RequirementSource: sizeTh.Source}
	if total, avail, err := r.env.Statfs(r.path(existing)); err != nil {
		size.Status, size.Detail = Skip, "cannot stat "+where
	} else {
		detail := fmt.Sprintf("filesystem of %s: %.1f GB total, %.1f GB free, %d GB needed", where, float64(total)/gb, float64(avail)/gb, sizeTh.Value)
		need := uint64(sizeTh.Value) * gb
		switch {
		case total >= need:
			size.Status, size.Detail = gate(sizeTh, Pass, detail)
		case total >= need/100*95:
			size.Status = Warn
			size.Detail = detail + "; the filesystem is just under the minimum, which filesystem overhead may explain (Vast measures this itself)"
			size.Remediation = dedHelp
		default:
			size.Status, size.Detail = gate(sizeTh, Fail, detail)
			size.Remediation = dedHelp
		}
	}
	r.add(size)

	fsTh := r.req.DockerStorageFS
	fsCheck := Check{ID: "storage_docker_fs", Title: "Docker storage filesystem", RequirementSource: fsTh.Source}
	if !haveMount {
		fsCheck.Status, fsCheck.Detail = Skip, "cannot determine the filesystem of "+where
	} else {
		ok := false
		for _, t := range fsTh.Value {
			if t == mount.FSType {
				ok = true
			}
		}
		detail := "filesystem type " + mount.FSType + " (expected one of: " + strings.Join(fsTh.Value, ", ") + ")"
		if ok {
			fsCheck.Status, fsCheck.Detail = gate(fsTh, Pass, detail)
		} else {
			fsCheck.Status, fsCheck.Detail = gate(fsTh, Fail, detail)
		}
		if fsCheck.Status != Pass {
			fsCheck.Remediation = "Check the filesystem requirement in the Vast host setup guide before preparing the Docker drive. Never reformat a drive that holds renter data." + neverBlind
		}
	}
	r.add(fsCheck)
}

func (r *runner) checkNetwork(ctx context.Context) {
	api := Check{ID: "network_api", Title: "HappyMining API reachable"}
	https := Check{ID: "network_https", Title: "Outbound HTTPS"}
	if r.env.Offline {
		api.Status, api.Detail = Skip, "skipped (--offline)"
		https.Status, https.Detail = Skip, "skipped (--offline)"
		r.add(api)
		r.add(https)
		return
	}
	if r.env.ProbeAPI == nil {
		api.Status, api.Detail = Skip, "no API URL configured"
	} else {
		pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		detail, err := r.env.ProbeAPI(pctx)
		cancel()
		if err != nil {
			api.Status, api.Detail = Fail, "cannot reach the HappyMining API: "+protocol.Truncate(err.Error(), 200)
			api.Remediation = "Check DNS, the firewall and HM_API_URL in /etc/happymining/agent.env. This only affects HappyMining monitoring; it does not stop Vast hosting."
		} else {
			api.Status, api.Detail = Pass, detail
		}
	}
	r.add(api)

	if r.env.ProbeHTTPS == nil || len(r.req.OutboundHTTPSProbes) == 0 {
		https.Status, https.Detail = Skip, "no probe configured"
	} else {
		var failures []string
		ok := ""
		for _, u := range r.req.OutboundHTTPSProbes {
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := r.env.ProbeHTTPS(pctx, u)
			cancel()
			if err == nil {
				ok = u
				break
			}
			failures = append(failures, u+": "+protocol.Truncate(err.Error(), 120))
		}
		if ok != "" {
			https.Status, https.Detail = Pass, "HTTPS request to "+ok+" succeeded with a verified certificate"
		} else {
			https.Status, https.Detail = Fail, "no HTTPS probe succeeded ("+strings.Join(failures, "; ")+")"
			https.Remediation = "Check the default route, DNS, the firewall and the system clock. Outbound HTTPS is needed for updates and for hosting."
		}
	}
	r.add(https)
}

func (r *runner) checkTimeSync(ctx context.Context) {
	c := Check{ID: "time_sync", Title: "Time synchronisation"}
	bin, err := execx.FindAbs(r.env.Root, "/usr/bin/timedatectl", "/bin/timedatectl")
	if err != nil {
		c.Status, c.Detail = Skip, "timedatectl not found"
		r.add(c)
		return
	}
	res, err := r.env.Runner.Run(ctx, 5*time.Second, bin, "show", "--property=NTPSynchronized", "--value")
	if err != nil || res.ExitCode != 0 {
		c.Status, c.Detail = Skip, "timedatectl did not answer"
		r.add(c)
		return
	}
	switch strings.TrimPrefix(strings.TrimSpace(string(res.Stdout)), "NTPSynchronized=") {
	case "yes":
		c.Status, c.Detail = Pass, "system clock is synchronised"
	case "no":
		c.Status, c.Detail = Warn, "system clock is not synchronised"
		c.Remediation = "Enable a time service (systemd-timesyncd or chrony). TLS and telemetry timestamps depend on a correct clock."
	default:
		c.Status, c.Detail = Skip, "unexpected timedatectl output"
	}
	r.add(c)
}

// dockerDebPackages are the Debian packages that provide a Docker engine.
var dockerDebPackages = []string{"docker-ce", "docker.io", "docker-engine", "moby-engine", "podman-docker"}

// installedPackages returns which of the wanted packages dpkg has in state
// "install ok installed". It only reads /var/lib/dpkg/status.
func (r *runner) installedPackages(wanted []string) []string {
	f, err := os.Open(r.path("/var/lib/dpkg/status"))
	if err != nil {
		return nil
	}
	defer f.Close()
	want := map[string]bool{}
	for _, w := range wanted {
		want[w] = true
	}
	var out []string
	current := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Package: "):
			current = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		case strings.HasPrefix(line, "Status: "):
			if want[current] && strings.TrimSpace(strings.TrimPrefix(line, "Status: ")) == "install ok installed" {
				out = append(out, current)
			}
		}
	}
	return out
}

func (r *runner) checkDocker() {
	th := r.req.DockerPackagesExpected
	c := Check{ID: "docker_install", Title: "Existing Docker installation", RequirementSource: th.Source}
	debs := r.installedPackages(dockerDebPackages)
	snap := r.exists("/snap/bin/docker") || r.exists("/var/snap/docker") || r.exists("/snap/docker")
	binary := r.exists("/usr/bin/dockerd") || r.exists("/usr/bin/docker") || r.exists("/usr/local/bin/dockerd")
	var found []string
	for _, d := range debs {
		found = append(found, d+" (deb)")
	}
	if snap {
		found = append(found, "docker (snap)")
	}
	keep := "HappyMining tools report the Docker installation and never install, remove or replace it."
	switch {
	case len(found) > 1:
		c.Status = Fail
		c.RequirementSource = ""
		c.Detail = "several Docker installations coexist: " + strings.Join(found, ", ") + " (HappyMining policy: one Docker engine per host)"
		c.Remediation = "Find out which engine is actually running containers before touching anything, then remove the unused one by hand. " + keep + neverBlind
	case snap:
		c.Status = Fail
		c.RequirementSource = ""
		c.Detail = "Docker is installed as a snap (HappyMining policy: a snap-packaged Docker is not supported for GPU hosting)"
		c.Remediation = "Do not remove it blindly: check what uses it first, then remove the snap by hand and follow the official Vast host setup guide for Docker. " + keep + neverBlind
	case len(debs) == 1:
		expected := false
		for _, e := range th.Value {
			if e == debs[0] {
				expected = true
			}
		}
		detail := debs[0] + " is installed (expected: " + strings.Join(th.Value, ", ") + "); it is left untouched"
		if expected {
			c.Status, c.Detail = gate(th, Pass, detail)
		} else {
			c.Status, c.Detail = gate(th, Fail, detail)
		}
		if c.Status != Pass {
			c.Remediation = "Compare with the Docker requirement in the official Vast host setup guide. " + keep
		}
	case binary:
		c.Status = Warn
		c.RequirementSource = ""
		c.Detail = "a docker binary exists but it does not come from a known package"
		c.Remediation = "Find out how this Docker was installed before installing the Vast host software. " + keep
	default:
		c.Status = Pass
		c.RequirementSource = ""
		c.Detail = "no Docker installation found; HappyMining does not install Docker"
	}
	r.add(c)
}

func (r *runner) checkVast() {
	th := r.req.VastDetectionPaths
	c := Check{ID: "vast_install", Title: "Existing Vast host installation", Status: Pass, RequirementSource: th.Source}
	var found []string
	for _, p := range th.Value {
		if r.exists(p) {
			found = append(found, p)
		}
	}
	note := ""
	if !th.Verified {
		note = " (the detection paths are not verified against Vast documentation)"
	}
	if len(found) > 0 {
		c.Detail = "found " + strings.Join(found, ", ") + note + ". The existing installation is preserved: HappyMining tools never modify, reinstall or remove Vast software."
	} else {
		c.Detail = "not found at the known locations" + note + ". Installing it is a manual step: see `happyminingctl vast-enroll-help`."
	}
	r.add(c)
}

func (r *runner) checkSecureBoot() {
	th := r.req.SecureBootDisabled
	c := Check{ID: "secure_boot", Title: "Secure Boot", RequirementSource: th.Source}
	if !r.exists("/sys/firmware/efi") {
		c.Status, c.Detail = gate(th, Pass, "not booted through UEFI, so Secure Boot is not active")
		r.add(c)
		return
	}
	matches, _ := filepath.Glob(r.path("/sys/firmware/efi/efivars/SecureBoot-*"))
	if len(matches) == 0 {
		c.Status, c.Detail = Skip, "Secure Boot state is not readable"
		r.add(c)
		return
	}
	data, err := os.ReadFile(matches[0])
	if err != nil || len(data) < 5 {
		c.Status, c.Detail = Skip, "Secure Boot state is not readable"
		r.add(c)
		return
	}
	enabled := data[4] == 1
	switch {
	case !th.Value:
		c.Status, c.Detail = Pass, fmt.Sprintf("Secure Boot enabled: %v (no requirement)", enabled)
	case enabled:
		c.Status, c.Detail = gate(th, Fail, "Secure Boot is enabled")
		c.Remediation = "Disable Secure Boot in the firmware setup. That needs a reboot." + neverBlind
	default:
		c.Status, c.Detail = gate(th, Pass, "Secure Boot is disabled")
	}
	r.add(c)
}

func (r *runner) checkNotChecked() {
	if len(r.req.NotCheckedByThisVersion) == 0 {
		return
	}
	var items []string
	source := ""
	for _, n := range r.req.NotCheckedByThisVersion {
		items = append(items, n.Requirement)
		if source == "" {
			source = n.Source
		}
	}
	r.add(Check{
		ID:                "not_checked",
		Title:             "Requirements preflight cannot check",
		Status:            Skip,
		Detail:            strings.Join(items, " / "),
		RequirementSource: source,
	})
}
