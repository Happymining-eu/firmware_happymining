// Package sim simulates machines without NVIDIA hardware. It pairs each
// simulated machine with a pairing code and then runs the real agent loop
// (same client, spool, sequence, backoff and operation code) with a synthetic
// collector. Every sample is marked "synthetic": true.
//
// A passing simulator run proves the software paths, not real hardware.
package sim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/agent"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/client"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/credential"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/enroll"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/logx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/redact"
)

// Options configures a simulation.
type Options struct {
	APIURL                string
	CAFile                string
	AllowInsecureLoopback bool
	// Machines is the number of simulated machines.
	Machines int
	// PairingCodes holds one code per machine that is not paired yet.
	PairingCodes []string
	// StateDir is the base directory; machine i keeps its state (identity,
	// credential, spool, sequence) in StateDir/machine-<i>.
	StateDir string
	// GPUModel is a short model name from Models; GPUs is the count per machine.
	GPUModel string
	GPUs     int
	// Interval between samples.
	Interval time.Duration
	// Samples per machine; 0 runs until the context is cancelled.
	Samples int
	// Seed makes the synthetic telemetry reproducible.
	Seed uint64
	// OutageAfter and OutageFor simulate an API outage per machine: after
	// OutageAfter samples were collected, requests fail without reaching the
	// server until OutageFor more samples were collected. The agent buffers
	// and then flushes. OutageFor == 0 disables it.
	OutageAfter int
	OutageFor   int
	// DuplicateEvery, if > 0, loses the response of every Nth heartbeat that
	// reached the server, so the agent resends samples the server already has.
	DuplicateEvery int
	BackoffBase    time.Duration
	BackoffCap     time.Duration
	SpoolQuota     int64
	Logger         *slog.Logger
}

// MachineResult is the outcome for one simulated machine.
type MachineResult struct {
	Index            int    `json:"index"`
	Hostname         string `json:"hostname"`
	DeviceID         string `json:"device_id"`
	MachineID        string `json:"machine_id"`
	SamplesCollected int    `json:"samples_collected"`
	SamplesDropped   uint64 `json:"samples_dropped"`
	SpoolLeft        int    `json:"spool_left"`
	FailedRequests   int64  `json:"failed_requests_injected"`
	LostResponses    int64  `json:"lost_responses_injected"`
	Error            string `json:"error,omitempty"`
}

// Summary is the outcome of a simulation.
type Summary struct {
	Synthetic bool            `json:"synthetic"`
	Machines  []MachineResult `json:"machines"`
}

// countingCollector counts collections so the fault transport can follow the
// outage schedule from another goroutine.
type countingCollector struct {
	inner *Synthetic
	n     atomic.Int64
}

func (c *countingCollector) Collect(ctx context.Context) (protocol.Sample, []string) {
	c.n.Add(1)
	return c.inner.Collect(ctx)
}

// faultTransport sits in front of the real HTTP transport.
type faultTransport struct {
	next           http.RoundTripper
	collected      *atomic.Int64
	outageAfter    int64
	outageFor      int64
	duplicateEvery int64
	heartbeats     atomic.Int64
	failed         atomic.Int64
	lost           atomic.Int64
}

var errSimulatedOutage = errors.New("simulated outage: request not sent")
var errSimulatedLostResponse = errors.New("simulated network failure: response lost after the server processed the request")

func (t *faultTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.outageFor > 0 {
		if n := t.collected.Load(); n > t.outageAfter && n <= t.outageAfter+t.outageFor {
			t.failed.Add(1)
			return nil, errSimulatedOutage
		}
	}
	resp, err := t.next.RoundTrip(req)
	if err != nil || !strings.HasSuffix(req.URL.Path, protocol.PathHeartbeat) {
		return resp, err
	}
	if t.duplicateEvery > 0 && t.heartbeats.Add(1)%t.duplicateEvery == 0 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, client.MaxResponseBytes))
		_ = resp.Body.Close()
		t.lost.Add(1)
		return nil, errSimulatedLostResponse
	}
	return resp, nil
}

func (o *Options) validate() error {
	if o.Machines < 1 || o.Machines > 1000 {
		return errors.New("machines must be between 1 and 1000")
	}
	if o.StateDir == "" {
		return errors.New("a state directory is required")
	}
	if o.Interval <= 0 {
		return errors.New("interval must be positive")
	}
	if o.GPUs < 0 || o.GPUs > protocol.MaxGPUs {
		return fmt.Errorf("gpus must be between 0 and %d", protocol.MaxGPUs)
	}
	if o.Samples < 0 || o.OutageAfter < 0 || o.OutageFor < 0 || o.DuplicateEvery < 0 {
		return errors.New("counts must not be negative")
	}
	if o.OutageFor > 0 && o.Samples > 0 && o.Samples <= o.OutageAfter+o.OutageFor {
		return errors.New("samples must be greater than outage-after + outage-for, otherwise the simulated outage never ends")
	}
	return nil
}

// Run pairs (where needed) and runs all machines until they have delivered
// Samples samples each, or until ctx is cancelled.
func Run(ctx context.Context, o Options) (Summary, error) {
	summary := Summary{Synthetic: true}
	if err := o.validate(); err != nil {
		return summary, err
	}
	model, err := LookupModel(o.GPUModel)
	if err != nil {
		return summary, err
	}
	if o.Logger == nil {
		o.Logger = logx.Discard()
	}
	if o.SpoolQuota <= 0 {
		o.SpoolQuota = 16 * 1024 * 1024
	}

	type machine struct {
		result MachineResult
		agent  *agent.Agent
		fault  *faultTransport
	}
	machines := make([]*machine, o.Machines)
	nextCode := 0
	for i := range machines {
		m := &machine{result: MachineResult{Index: i, Hostname: fmt.Sprintf("sim-gpu-%03d", i+1)}}
		machines[i] = m
		stateDir := filepath.Join(o.StateDir, fmt.Sprintf("machine-%03d", i+1))
		coll := &countingCollector{inner: NewSynthetic(model, o.GPUs, o.Seed+uint64(i), nil)}
		m.fault = &faultTransport{
			collected: &coll.n, outageAfter: int64(o.OutageAfter), outageFor: int64(o.OutageFor),
			duplicateEvery: int64(o.DuplicateEvery),
		}
		cl, err := client.New(client.Options{
			BaseURL: o.APIURL, CAFile: o.CAFile, AllowInsecureLoopback: o.AllowInsecureLoopback,
			WrapTransport: func(rt http.RoundTripper) http.RoundTripper {
				m.fault.next = rt
				return m.fault
			},
		})
		if err != nil {
			return summary, err
		}
		redactor := redact.New()
		a, err := agent.New(agent.Options{
			StateDir: stateDir, SpoolDir: filepath.Join(stateDir, "spool"), SpoolQuotaBytes: o.SpoolQuota,
			Interval: o.Interval, IgnoreServerInterval: true,
			BackoffBase: o.BackoffBase, BackoffCap: o.BackoffCap,
			Client: cl, Collector: coll, Synthetic: true,
			BootID:   simBootID(o.Seed + uint64(i)),
			Logger:   o.Logger.With("machine", m.result.Hostname),
			Redactor: redactor, StopAfterSamples: o.Samples,
			Rand: rand.New(rand.NewPCG(o.Seed+uint64(i), 7)).Int64N,
		})
		if err != nil {
			return summary, fmt.Errorf("%s: %w", m.result.Hostname, err)
		}
		m.agent = a
		cred, err := credential.Load(credential.Path(stateDir))
		if errors.Is(err, credential.ErrNotPaired) {
			if nextCode >= len(o.PairingCodes) {
				return summary, fmt.Errorf("%s is not paired and no pairing code is left (give one code per unpaired machine)", m.result.Hostname)
			}
			code := o.PairingCodes[nextCode]
			nextCode++
			redactor.AddSecret(code)
			cred, err = enroll.Pair(ctx, enroll.Params{
				Client: cl, StateDir: stateDir, Code: code, Hostname: m.result.Hostname,
				OS: protocol.OSInfo{ID: "ubuntu", VersionID: "24.04", Kernel: "simulated", Arch: "amd64"},
			})
		}
		if err != nil {
			return summary, fmt.Errorf("%s: %w", m.result.Hostname, err)
		}
		m.result.DeviceID, m.result.MachineID = cred.DeviceID, cred.MachineID
	}

	var wg sync.WaitGroup
	for _, m := range machines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer m.agent.Close()
			if err := m.agent.Run(ctx); err != nil {
				m.result.Error = err.Error()
			}
		}()
	}
	wg.Wait()

	var failed []string
	for _, m := range machines {
		m.result.SamplesCollected = m.agent.Collected()
		m.result.SamplesDropped = m.agent.Dropped()
		m.result.SpoolLeft = m.agent.SpoolLen()
		m.result.FailedRequests = m.fault.failed.Load()
		m.result.LostResponses = m.fault.lost.Load()
		if m.result.Error != "" {
			failed = append(failed, m.result.Hostname+": "+m.result.Error)
		}
		summary.Machines = append(summary.Machines, m.result)
	}
	if len(failed) > 0 {
		return summary, fmt.Errorf("%d machine(s) failed: %v", len(failed), failed)
	}
	return summary, nil
}

// simBootID derives a reproducible boot id from the seed.
func simBootID(seed uint64) string {
	r := rand.New(rand.NewPCG(seed, 0xb007))
	return fmt.Sprintf("%08x-%04x-4%03x-a%03x-%012x",
		r.Uint32(), r.Uint32()&0xffff, r.Uint32()&0xfff, r.Uint32()&0xfff, r.Uint64()&0xffffffffffff)
}
