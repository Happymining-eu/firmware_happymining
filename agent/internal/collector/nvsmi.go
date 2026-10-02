package collector

import (
	"math"
	"strconv"
	"strings"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
)

// NvidiaSMICandidates are the absolute paths where nvidia-smi is looked up.
// $PATH is never used.
var NvidiaSMICandidates = []string{"/usr/bin/nvidia-smi", "/usr/local/bin/nvidia-smi", "/bin/nvidia-smi"}

// NvidiaSMIArgs is the fixed query. The field order is what ParseNvidiaSMI
// expects.
var NvidiaSMIArgs = []string{
	"--query-gpu=index,uuid,name,driver_version,memory.total,memory.used,utilization.gpu,power.draw,temperature.gpu,fan.speed",
	"--format=csv,noheader,nounits",
}

const nvsmiFields = 10

// cleanString returns "" for nvidia-smi's "no value" markers.
func cleanString(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "[") || strings.EqualFold(v, "N/A") {
		return ""
	}
	return protocol.Truncate(v, protocol.MaxStringLen)
}

// parseNumber returns nil for anything that is not a finite number inside
// [lo, hi]: "[N/A]", "[Not Supported]", "N/A", "", "[Unknown Error]", ...
// A missing value must become JSON null, never 0.
func parseNumber(v string, lo, hi float64) *float64 {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < lo || f > hi {
		return nil
	}
	return &f
}

func parseInt(v string, lo, hi float64) *int64 {
	f := parseNumber(v, lo, hi)
	if f == nil {
		return nil
	}
	n := int64(math.Round(*f))
	return &n
}

// ParseNvidiaSMI parses the CSV output of the fixed query. Lines that cannot
// be attributed to a GPU index are skipped and counted.
func ParseNvidiaSMI(out string) (gpus []protocol.GPU, skipped int) {
	gpus = []protocol.GPU{}
	seen := map[int]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < nvsmiFields {
			skipped++
			continue
		}
		if extra := len(fields) - nvsmiFields; extra > 0 {
			// A comma inside the GPU name: glue the name back together.
			name := strings.Join(fields[2:3+extra], ",")
			fields = append(append(fields[:2:2], name), fields[3+extra:]...)
		}
		idx := parseInt(fields[0], 0, 4095)
		if idx == nil || seen[int(*idx)] {
			skipped++
			continue
		}
		if len(gpus) >= protocol.MaxGPUs {
			skipped++
			continue
		}
		seen[int(*idx)] = true
		gpus = append(gpus, protocol.GPU{
			Index:         int(*idx),
			UUID:          cleanString(fields[1]),
			Name:          cleanString(fields[2]),
			DriverVersion: cleanString(fields[3]),
			VRAMTotalMiB:  parseInt(fields[4], 0, 16*1024*1024),
			VRAMUsedMiB:   parseInt(fields[5], 0, 16*1024*1024),
			UtilPct:       parseInt(fields[6], 0, 100),
			PowerW:        parseNumber(fields[7], 0, 10000),
			TempC:         parseInt(fields[8], -100, 250),
			FanPct:        parseInt(fields[9], 0, 100),
		})
	}
	return gpus, skipped
}
