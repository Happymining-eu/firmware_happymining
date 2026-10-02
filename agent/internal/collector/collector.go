// Package collector gathers one telemetry sample.
//
// Privacy boundary: the collector reads host-level counters only. It never
// lists processes, never inspects containers (names, images, environment,
// storage) and never reads command lines. It does not use the Docker socket.
// The only things it executes are nvidia-smi with a fixed query and
// `systemctl is-active` / `systemctl show` for a fixed allowlist of units.
package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/config"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/execx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
)

// Collector produces one sample without seq, collected_at and synthetic, which
// the agent runtime fills in. Warnings describe partial failures; they are
// logged locally and never sent.
type Collector interface {
	Collect(ctx context.Context) (protocol.Sample, []string)
}

// ServiceUnits is the fixed allowlist of units whose state is reported.
var ServiceUnits = []string{"docker", "vastai", "nvidia-persistenced"}

// VastUnit is the unit of the official Vast host software as far as this
// agent knows. The name is not verified against Vast documentation.
const VastUnit = "vastai"

// SystemctlCandidates are the absolute paths where systemctl is looked up.
var SystemctlCandidates = []string{"/usr/bin/systemctl", "/bin/systemctl"}

// DefaultMounts are always reported when they exist.
var DefaultMounts = []string{"/", "/var/lib/docker"}

// Timeouts for external commands.
const (
	nvidiaSMITimeout = 15 * time.Second
	systemctlTimeout = 5 * time.Second
)

// StatfsFunc returns total and available bytes of the filesystem at path.
type StatfsFunc func(path string) (total, avail uint64, err error)

// Real collects from the running host.
type Real struct {
	// Root is prepended to every path the collector reads ("" in production,
	// a temporary directory in tests).
	Root   string
	Runner execx.Runner
	Statfs StatfsFunc
	// ExtraMounts are reported in addition to DefaultMounts.
	ExtraMounts []string
	// VastMachineIDFile is the host-local Vast machine identifier file. Only
	// its SHA-256 is ever reported, and only if this process may read it.
	VastMachineIDFile string

	prev    cpuTimes
	hasPrev bool
}

// NewReal returns a collector for the running host.
func NewReal(extraMounts []string, vastMachineIDFile string) *Real {
	return &Real{Runner: execx.OS{}, Statfs: OSStatfs, ExtraMounts: extraMounts, VastMachineIDFile: vastMachineIDFile}
}

// OSStatfs is the real StatfsFunc.
func OSStatfs(path string) (uint64, uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bsize := uint64(st.Bsize)
	return st.Blocks * bsize, st.Bavail * bsize, nil
}

func (r *Real) path(p string) string { return filepath.Join(r.Root, p) }

func (r *Real) read(p string, limit int64) ([]byte, error) {
	f, err := os.Open(r.path(p))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

// Collect implements Collector.
func (r *Real) Collect(ctx context.Context) (protocol.Sample, []string) {
	var warn []string
	s := protocol.Sample{}

	if data, err := r.read("/proc/uptime", 256); err == nil {
		if f := parseFirstFloat(data); f != nil {
			u := uint64(*f)
			s.UptimeS = &u
		}
	} else {
		warn = append(warn, "uptime: "+err.Error())
	}

	s.CPU = r.cpu(&warn)

	if data, err := r.read("/proc/meminfo", 64*1024); err == nil {
		s.Memory.TotalBytes, s.Memory.AvailableBytes = ParseMemInfo(data)
	} else {
		warn = append(warn, "meminfo: "+err.Error())
	}

	s.Disks = r.Disks(&warn)
	s.GPUs = r.GPUs(ctx, &warn)
	s.Services = r.Services(ctx, &warn)
	s.Vast = r.vast(s.Services)
	return s, warn
}

func (r *Real) cpu(warn *[]string) protocol.CPU {
	var c protocol.CPU
	if data, err := r.read("/proc/cpuinfo", 8*1024*1024); err == nil {
		info := ParseCPUInfo(data)
		c.Model = protocol.Truncate(info.Model, protocol.MaxStringLen)
		if info.Logical > 0 {
			n := info.Logical
			c.Cores = &n
		}
	} else {
		*warn = append(*warn, "cpuinfo: "+err.Error())
	}
	if data, err := r.read("/proc/loadavg", 256); err == nil {
		c.Load1 = parseFirstFloat(data)
	} else {
		*warn = append(*warn, "loadavg: "+err.Error())
	}
	if data, err := r.read("/proc/stat", 64*1024); err == nil {
		if cur, ok := parseProcStat(data); ok {
			if r.hasPrev {
				c.UtilPct = cpuUtil(r.prev, cur)
			}
			r.prev, r.hasPrev = cur, true
		}
	} else {
		*warn = append(*warn, "stat: "+err.Error())
	}
	return c
}

// Disks reports the configured mounts that exist.
func (r *Real) Disks(warn *[]string) []protocol.Disk {
	disks := []protocol.Disk{}
	var mounts []Mount
	if data, err := r.read("/proc/mounts", 1024*1024); err == nil {
		mounts = ParseMounts(data)
	} else {
		*warn = append(*warn, "mounts: "+err.Error())
	}
	seen := map[string]bool{}
	for _, m := range append(append([]string{}, DefaultMounts...), r.ExtraMounts...) {
		if seen[m] || len(disks) >= protocol.MaxDisks {
			continue
		}
		seen[m] = true
		if _, err := os.Stat(r.path(m)); err != nil {
			continue // not present on this host
		}
		d := protocol.Disk{Mount: protocol.Truncate(m, protocol.MaxStringLen)}
		if mt, ok := MountFor(mounts, m); ok {
			d.FS = protocol.Truncate(mt.FSType, protocol.MaxStringLen)
		}
		if r.Statfs != nil {
			if total, avail, err := r.Statfs(r.path(m)); err == nil {
				d.TotalBytes, d.AvailBytes = &total, &avail
			} else {
				*warn = append(*warn, fmt.Sprintf("statfs %s: %v", m, err))
			}
		}
		disks = append(disks, d)
	}
	return disks
}

// GPUs runs the fixed nvidia-smi query. A host without nvidia-smi reports an
// empty list.
func (r *Real) GPUs(ctx context.Context, warn *[]string) []protocol.GPU {
	bin, err := execx.FindAbs(r.Root, NvidiaSMICandidates...)
	if err != nil {
		*warn = append(*warn, "nvidia-smi not found")
		return []protocol.GPU{}
	}
	res, err := r.Runner.Run(ctx, nvidiaSMITimeout, bin, NvidiaSMIArgs...)
	if err != nil {
		*warn = append(*warn, "nvidia-smi: "+err.Error())
		return []protocol.GPU{}
	}
	if res.ExitCode != 0 {
		*warn = append(*warn, fmt.Sprintf("nvidia-smi exited with status %d", res.ExitCode))
		return []protocol.GPU{}
	}
	gpus, skipped := ParseNvidiaSMI(string(res.Stdout))
	if skipped > 0 {
		*warn = append(*warn, fmt.Sprintf("nvidia-smi: %d unparseable line(s) skipped", skipped))
	}
	return gpus
}

// Services reports the state of the allowlisted units.
func (r *Real) Services(ctx context.Context, warn *[]string) map[string]string {
	out := make(map[string]string, len(ServiceUnits))
	bin, err := execx.FindAbs(r.Root, SystemctlCandidates...)
	for _, unit := range ServiceUnits {
		if err != nil {
			out[unit] = protocol.ServiceUnknown
			continue
		}
		out[unit] = UnitState(ctx, r.Runner, bin, unit)
	}
	if err != nil {
		*warn = append(*warn, "systemctl not found")
	}
	return out
}

// UnitState maps `systemctl is-active <unit>.service` to a protocol service
// state. Because is-active prints "inactive" for a unit that does not exist,
// a second read-only query of LoadState tells "not-installed" apart.
func UnitState(ctx context.Context, runner execx.Runner, systemctl, unit string) string {
	res, err := runner.Run(ctx, systemctlTimeout, systemctl, "is-active", unit+".service")
	if err != nil {
		return protocol.ServiceUnknown
	}
	state := strings.TrimSpace(string(res.Stdout))
	switch state {
	case protocol.ServiceActive, protocol.ServiceFailed, protocol.ServiceActivating:
		return state
	case protocol.ServiceInactive, "unknown", "":
		load, err := runner.Run(ctx, systemctlTimeout, systemctl, "show", "--property=LoadState", "--value", unit+".service")
		if err != nil {
			return protocol.ServiceUnknown
		}
		switch strings.TrimPrefix(strings.TrimSpace(string(load.Stdout)), "LoadState=") {
		case "not-found":
			return protocol.ServiceNotInstalled
		case "":
			return protocol.ServiceUnknown
		}
		if state == protocol.ServiceInactive {
			return protocol.ServiceInactive
		}
	}
	return protocol.ServiceUnknown
}

// vastUnitDirs are the directories where a vastai.service unit file would be.
var vastUnitDirs = []string{"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"}

// VastInstalled reports, read-only, whether the official Vast host software
// appears to be installed.
func (r *Real) VastInstalled(services map[string]string) bool {
	switch services[VastUnit] {
	case protocol.ServiceActive, protocol.ServiceInactive, protocol.ServiceFailed, protocol.ServiceActivating:
		return true
	}
	for _, dir := range vastUnitDirs {
		if _, err := os.Lstat(r.path(filepath.Join(dir, VastUnit+".service"))); err == nil {
			return true
		}
	}
	if r.VastMachineIDFile != "" {
		if fi, err := os.Stat(r.path(filepath.Dir(r.VastMachineIDFile))); err == nil && fi.IsDir() {
			return true
		}
	}
	return false
}

func (r *Real) vast(services map[string]string) protocol.Vast {
	return protocol.Vast{DaemonInstalled: r.VastInstalled(services), MachineIDHint: r.vastHint()}
}

// vastHint returns "sha256:<hex>" of the trimmed content of the numeric Vast
// machine id file, or nil if this (unprivileged) process cannot read it or the
// content is not a plain number. The raw identifier never leaves this
// function.
//
// The hint is untrusted evidence for an operator. Vast's key file
// (vastai_kaalia/machine_id) is a secret and is refused outright, whatever the
// configuration says.
func (r *Real) vastHint() *string {
	if r.VastMachineIDFile == "" || config.IsVastSecretFile(r.VastMachineIDFile) {
		return nil
	}
	data, err := r.read(r.VastMachineIDFile, 4096)
	if err != nil {
		return nil
	}
	id := strings.TrimSpace(string(data))
	if !isDecimalID(id) {
		// Anything that is not a short decimal number is not the numeric
		// machine id and might be a secret: do not derive anything from it.
		return nil
	}
	sum := sha256.Sum256([]byte(id))
	hint := "sha256:" + hex.EncodeToString(sum[:])
	return &hint
}

// isDecimalID reports whether s looks like a numeric machine id: 1 to 12
// ASCII digits and nothing else.
func isDecimalID(s string) bool {
	if len(s) == 0 || len(s) > 12 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
