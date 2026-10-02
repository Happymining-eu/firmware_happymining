package sim

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
)

// GPUModel describes a simulated GPU. The numbers are plausible values chosen
// for the simulator; they are not measurements and not vendor specifications.
type GPUModel struct {
	Name    string
	VRAMMiB int64
	IdleW   float64
	MaxW    float64
}

// Models are the GPU models the simulator knows, keyed by a short name.
var Models = map[string]GPUModel{
	"rtx3090": {Name: "NVIDIA GeForce RTX 3090", VRAMMiB: 24576, IdleW: 30, MaxW: 350},
	"rtx4090": {Name: "NVIDIA GeForce RTX 4090", VRAMMiB: 24564, IdleW: 25, MaxW: 450},
	"rtx5090": {Name: "NVIDIA GeForce RTX 5090", VRAMMiB: 32607, IdleW: 30, MaxW: 575},
	"a6000":   {Name: "NVIDIA RTX A6000", VRAMMiB: 49140, IdleW: 25, MaxW: 300},
	"l40s":    {Name: "NVIDIA L40S", VRAMMiB: 46068, IdleW: 35, MaxW: 350},
	"h100":    {Name: "NVIDIA H100 80GB HBM3", VRAMMiB: 81559, IdleW: 70, MaxW: 700},
}

// ModelNames lists the known short names.
func ModelNames() []string {
	names := make([]string, 0, len(Models))
	for n := range Models {
		names = append(names, n)
	}
	return names
}

// LookupModel finds a model by short name (case-insensitive).
func LookupModel(name string) (GPUModel, error) {
	if m, ok := Models[strings.ToLower(strings.TrimSpace(name))]; ok {
		return m, nil
	}
	return GPUModel{}, fmt.Errorf("unknown GPU model %q (known: %s)", name, strings.Join(ModelNames(), ", "))
}

// Synthetic is a collector that fabricates telemetry. Every sample it feeds
// is marked "synthetic": true by the agent runtime; it must never be used to
// represent a real machine.
type Synthetic struct {
	model   GPUModel
	gpus    int
	rng     *rand.Rand
	started time.Time
	now     func() time.Time
	uuids   []string
	util    []float64
	bootSec uint64
}

// NewSynthetic returns a deterministic synthetic collector for one machine.
func NewSynthetic(model GPUModel, gpus int, seed uint64, now func() time.Time) *Synthetic {
	if now == nil {
		now = time.Now
	}
	if gpus < 0 {
		gpus = 0
	}
	if gpus > protocol.MaxGPUs {
		gpus = protocol.MaxGPUs
	}
	s := &Synthetic{
		model: model, gpus: gpus, now: now, started: now(),
		rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
	}
	s.bootSec = 3600 + uint64(s.rng.IntN(30*24*3600))
	for i := 0; i < gpus; i++ {
		s.uuids = append(s.uuids, fmt.Sprintf("GPU-SIM-%08x-%04x-%04x-%04x-%012x",
			s.rng.Uint32(), s.rng.Uint32()&0xffff, s.rng.Uint32()&0xffff, s.rng.Uint32()&0xffff, s.rng.Uint64()&0xffffffffffff))
		s.util = append(s.util, float64(s.rng.IntN(100)))
	}
	return s
}

func ptr[T any](v T) *T { return &v }

// Collect implements collector.Collector.
func (s *Synthetic) Collect(context.Context) (protocol.Sample, []string) {
	elapsed := uint64(s.now().Sub(s.started) / time.Second)
	sample := protocol.Sample{
		UptimeS: ptr(s.bootSec + elapsed),
		CPU: protocol.CPU{
			Model:   "Simulated CPU (HappyMining simulator)",
			Cores:   ptr(max(8, 4*s.gpus)),
			Load1:   ptr(math.Round(s.rng.Float64()*400) / 100),
			UtilPct: ptr(math.Round(s.rng.Float64()*300) / 10),
		},
		Memory: protocol.Memory{
			TotalBytes:     ptr(uint64(max(1, s.gpus)) * uint64(s.model.VRAMMiB) * 1024 * 1024 * 2),
			AvailableBytes: ptr(uint64(max(1, s.gpus)) * uint64(s.model.VRAMMiB) * 1024 * 1024),
		},
		Disks: []protocol.Disk{
			{Mount: "/", FS: "ext4", TotalBytes: ptr(uint64(250e9)), AvailBytes: ptr(uint64(200e9) - uint64(s.rng.IntN(1e9)))},
			{Mount: "/var/lib/docker", FS: "xfs", TotalBytes: ptr(uint64(2000e9)), AvailBytes: ptr(uint64(1500e9) - uint64(s.rng.IntN(1e10)))},
		},
		GPUs: []protocol.GPU{},
		Services: map[string]string{
			"docker":              protocol.ServiceActive,
			"vastai":              protocol.ServiceActive,
			"nvidia-persistenced": protocol.ServiceActive,
		},
		// A simulated machine has no Vast machine identifier: the hint stays null.
		Vast: protocol.Vast{DaemonInstalled: true, MachineIDHint: nil},
	}
	for i := 0; i < s.gpus; i++ {
		// A slow random walk keeps consecutive samples plausible.
		s.util[i] = math.Max(0, math.Min(100, s.util[i]+float64(s.rng.IntN(41)-20)))
		load := s.util[i] / 100
		gpu := protocol.GPU{
			Index:         i,
			UUID:          s.uuids[i],
			Name:          s.model.Name,
			DriverVersion: "550.120",
			VRAMTotalMiB:  ptr(s.model.VRAMMiB),
			VRAMUsedMiB:   ptr(int64(float64(s.model.VRAMMiB) * load * 0.9)),
			UtilPct:       ptr(int64(s.util[i])),
			PowerW:        ptr(math.Round((s.model.IdleW+(s.model.MaxW-s.model.IdleW)*load)*10) / 10),
			TempC:         ptr(int64(35 + 45*load)),
			FanPct:        ptr(int64(30 + 60*load)),
		}
		// Data-centre cards report no fan: exercise the null path.
		if strings.Contains(s.model.Name, "H100") || strings.Contains(s.model.Name, "L40S") {
			gpu.FanPct = nil
		}
		sample.GPUs = append(sample.GPUs, gpu)
	}
	return sample, nil
}
