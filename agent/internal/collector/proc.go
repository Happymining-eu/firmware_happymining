package collector

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// CPUInfo is what the agent and the preflight need from /proc/cpuinfo.
type CPUInfo struct {
	Model         string
	Logical       int
	PhysicalCores int // 0 when topology fields are absent
	Flags         map[string]bool
}

// ParseCPUInfo parses /proc/cpuinfo.
func ParseCPUInfo(data []byte) CPUInfo {
	info := CPUInfo{Flags: map[string]bool{}}
	cores := map[string]bool{}
	physical, haveFlags := "", false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch key {
		case "processor":
			info.Logical++
			physical = ""
		case "model name":
			if info.Model == "" {
				info.Model = value
			}
		case "physical id":
			physical = value
		case "core id":
			cores[physical+"/"+value] = true
		case "flags", "Features":
			if !haveFlags {
				for _, f := range strings.Fields(value) {
					info.Flags[f] = true
				}
				haveFlags = true
			}
		}
	}
	info.PhysicalCores = len(cores)
	return info
}

// cpuTimes is the aggregate "cpu" line of /proc/stat.
type cpuTimes struct {
	total uint64
	idle  uint64
}

func parseProcStat(data []byte) (cpuTimes, bool) {
	line, _, _ := strings.Cut(string(data), "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuTimes{}, false
	}
	var t cpuTimes
	// user nice system idle iowait irq softirq steal (guest values are already
	// included in user and nice).
	for i, f := range fields[1:] {
		if i >= 8 {
			break
		}
		n, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return cpuTimes{}, false
		}
		t.total += n
		if i == 3 || i == 4 {
			t.idle += n
		}
	}
	return t, true
}

// cpuUtil returns the busy percentage between two readings, or nil.
func cpuUtil(prev, cur cpuTimes) *float64 {
	if cur.total <= prev.total || cur.idle < prev.idle {
		return nil
	}
	dTotal := float64(cur.total - prev.total)
	dIdle := float64(cur.idle - prev.idle)
	if dIdle > dTotal {
		return nil
	}
	pct := 100 * (1 - dIdle/dTotal)
	pct = float64(int64(pct*10+0.5)) / 10
	return &pct
}

// ParseMemInfo returns MemTotal and MemAvailable in bytes.
func ParseMemInfo(data []byte) (total, available *uint64) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		if len(fields) > 1 && fields[1] == "kB" {
			n *= 1024
		}
		switch key {
		case "MemTotal":
			v := n
			total = &v
		case "MemAvailable":
			v := n
			available = &v
		}
	}
	return total, available
}

func parseFirstFloat(data []byte) *float64 {
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return nil
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || f < 0 {
		return nil
	}
	return &f
}

// Mount is one line of /proc/mounts.
type Mount struct {
	Device string
	Point  string
	FSType string
}

// ParseMounts parses /proc/mounts.
func ParseMounts(data []byte) []Mount {
	var out []Mount
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		out = append(out, Mount{Device: unescapeMount(fields[0]), Point: unescapeMount(fields[1]), FSType: fields[2]})
	}
	return out
}

// unescapeMount decodes the octal escapes of /proc/mounts (\040 for a space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// MountFor returns the mount that contains path: the one with the longest
// mount point that is a path prefix. Later entries win over earlier ones with
// the same mount point (the later mount hides the earlier).
func MountFor(mounts []Mount, path string) (Mount, bool) {
	best, found := Mount{}, false
	for _, m := range mounts {
		if !isPathPrefix(m.Point, path) {
			continue
		}
		if !found || len(m.Point) >= len(best.Point) {
			best, found = m, true
		}
	}
	return best, found
}

func isPathPrefix(prefix, path string) bool {
	if prefix == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}
